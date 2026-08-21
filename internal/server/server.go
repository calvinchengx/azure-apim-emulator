// Package server assembles management, gateway, persistence, and control APIs.
package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/arm"
	"github.com/calvinchengx/azure-apim-emulator/internal/auth"
	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/config"
	"github.com/calvinchengx/azure-apim-emulator/internal/gateway"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

const (
	defaultSubscription  = "00000000-0000-0000-0000-000000000000"
	defaultResourceGroup = "emulator-rg"
)

// Server owns all emulator components.
type Server struct {
	Cfg     *config.Config
	Clock   *clock.Clock
	Store   *store.Store
	Gateway *gateway.Runtime
	ARM     *arm.Handler
	// PolicyLoadFailures are the stored documents Restore could not compile at
	// startup. Kept so a caller can see what was tolerated rather than only read
	// it in the log.
	PolicyLoadFailures       []gateway.PolicyFailure
	mux                      *http.ServeMux
	portalUpsertAPI          func(model.API) (model.API, error)
	portalUpsertProduct      func(model.Product) (model.Product, error)
	portalUpsertBackend      func(model.Backend) (model.Backend, error)
	portalUpsertNamedValue   func(model.NamedValue) (model.NamedValue, error)
	portalUpsertCertificate  func(model.Certificate) (model.Certificate, error)
	portalUpsertTag          func(model.Tag) (model.Tag, error)
	portalUpsertGroup        func(model.Group) (model.Group, error)
	portalUpsertSubscription func(model.Subscription) (model.Subscription, error)
	portalUpsertUser         func(model.User) (model.User, error)
}

// New wires a server. Overrides are intended for in-process tests.
func New(cfg *config.Config, validator auth.RequestValidator, backendClient, jwksClient *http.Client) (*Server, error) {
	ck := clock.New()
	st, err := store.Open(cfg.DataDir, ck)
	if err != nil {
		return nil, err
	}
	if validator == nil {
		if cfg.DisableAuth {
			validator = auth.AllowAll{}
		} else {
			validator = auth.New(cfg.EntraIssuer, cfg.EntraJWKSURL, cfg.EntraTLSInsecure, ck.Now, jwksClient)
		}
	}
	runtime := gateway.New(cfg.DefaultService, backendClient)
	if tokenValidator, ok := validator.(*auth.Validator); ok {
		runtime.SetPolicyTokenValidator(tokenValidator.ValidateToken)
	}
	s := &Server{Cfg: cfg, Clock: ck, Store: st, Gateway: runtime, mux: http.NewServeMux(), portalUpsertAPI: st.UpsertAPI, portalUpsertProduct: st.UpsertProduct, portalUpsertBackend: st.UpsertBackend, portalUpsertNamedValue: st.UpsertNamedValue, portalUpsertCertificate: st.UpsertCertificate, portalUpsertTag: st.UpsertTag, portalUpsertGroup: st.UpsertGroup, portalUpsertSubscription: st.UpsertSubscription, portalUpsertUser: st.UpsertUser}
	s.ARM = &arm.Handler{
		Store: st, Auth: validator,
		Activate:               func() error { return runtime.Activate(st, cfg.StrictPolicies) },
		EnforceRBAC:            cfg.EnforceRBAC,
		EnforceTiers:           cfg.EnforceTiers,
		RBACOwner:              cfg.RBACOwner,
		ValidatePolicy:         func(value string) error { _, err := policy.Compile(value, cfg.StrictPolicies); return err },
		ValidateResolverPolicy: func(value string) error { _, err := policy.CompileHTTPDataSource(value); return err },
		LoginLink: func(providerID, authorizationID, redirect string) (string, error) {
			return runtime.CredentialLoginLink(st, providerID, authorizationID, redirect)
		},
		ConfirmConsent: func(providerID, authorizationID, code string) error {
			return runtime.CredentialConfirmConsent(st, providerID, authorizationID, code)
		},
		ImportClient: backendClient,
		ExportKey:    []byte(store.NewOpaqueID()),
	}
	seed := model.Service{SubscriptionID: defaultSubscription, ResourceGroup: defaultResourceGroup, Name: cfg.DefaultService, Location: cfg.Location, SKUName: "Developer", SKUCapacity: 1, PublisherName: "Local Emulator", PublisherEmail: "local@azure-apim-emulator.test"}
	if _, err := st.GetService(seed.ID()); errors.Is(err, store.ErrNotFound) {
		if _, err := st.UpsertService(seed); err != nil {
			_ = st.Close()
			return nil, err
		}
	} else if err != nil {
		_ = st.Close()
		return nil, err
	}
	// Restore, not Activate: a document the store already holds must not keep the
	// emulator from starting, because the ARM API that could replace it is what
	// fails to start. Each one is reported here and again on every request that
	// reaches it.
	failures, err := runtime.Restore(st, cfg.StrictPolicies)
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	s.PolicyLoadFailures = failures
	for _, failure := range failures {
		log.Printf("azure-apim-emulator: stored policy will fail on every request that reaches it: %v", failure)
	}
	s.register()
	return s, nil
}

// Handler returns the root HTTP handler.
// Handler serves the emulator.
//
// The path is normalised BEFORE the mux sees it, because ServeMux redirects a
// path needing cleaning rather than dispatching it. An SDK that appends an
// absolute ARM scope to its endpoint produces a doubled slash
// (`{endpoint}` + `/subscriptions/...`), which Azure accepts and the
// Microsoft.Authorization client emits as a matter of course. A 301 is worse
// than it sounds: the SDK surfaces it as a transport failure carrying no error
// code, so the caller cannot tell what was wrong.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if collapsed := collapseSlashes(r.URL.Path); collapsed != r.URL.Path {
			r = r.Clone(r.Context())
			r.URL.Path = collapsed
			r.RequestURI = collapsed
			if r.URL.RawQuery != "" {
				r.RequestURI += "?" + r.URL.RawQuery
			}
		}
		s.mux.ServeHTTP(w, r)
	})
}

// Close releases the database.
func (s *Server) Close() error { return s.Store.Close() }

func (s *Server) register() {
	s.mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "now": s.Clock.Now(), "service": s.Cfg.DefaultService})
	})
	s.mux.HandleFunc("GET /_emulator/arm/operations/{id}", arm.OperationStatus)
	s.mux.HandleFunc("GET /_emulator/clock", func(w http.ResponseWriter, r *http.Request) {
		offset, frozen, now := s.Clock.State()
		writeJSON(w, http.StatusOK, map[string]any{"offset": offset, "frozen": frozen, "now": now})
	})
	s.mux.HandleFunc("POST /_emulator/clock", s.updateClock)
	s.mux.HandleFunc("GET /_emulator/traces/{id}", func(w http.ResponseWriter, r *http.Request) {
		trace, ok := s.Gateway.GetTrace(r.PathValue("id"))
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "trace not found"})
			return
		}
		writeJSON(w, http.StatusOK, trace)
	})
	s.mux.HandleFunc("GET /_emulator/portal/", s.portal)
	s.mux.HandleFunc("GET /_emulator/portal/api/status", s.portalStatus)
	s.mux.HandleFunc("GET /_emulator/portal/api/snapshot", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, s.Gateway.SnapshotSummary())
	})
	s.mux.HandleFunc("GET /_emulator/portal/api/parity", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"p1": map[string]any{"status": "in-progress", "verified": true}, "coverage": "100.0%"})
	})
	s.mux.HandleFunc("GET /_emulator/portal/api/faults", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.Gateway.FaultsSnapshot()) })
	s.mux.HandleFunc("GET /_emulator/portal/api/diagnostics", s.portalDiagnostics)
	s.mux.HandleFunc("GET /_emulator/portal/api/resource", s.portalResource)
	s.mux.HandleFunc("PUT /_emulator/portal/api/resource", s.portalResource)
	s.mux.HandleFunc("GET /_emulator/portal/api/product", s.portalProduct)
	s.mux.HandleFunc("PUT /_emulator/portal/api/product", s.portalProduct)
	s.mux.HandleFunc("GET /_emulator/portal/api/backend", s.portalBackend)
	s.mux.HandleFunc("PUT /_emulator/portal/api/backend", s.portalBackend)
	s.mux.HandleFunc("GET /_emulator/portal/api/named-value", s.portalNamedValue)
	s.mux.HandleFunc("PUT /_emulator/portal/api/named-value", s.portalNamedValue)
	s.mux.HandleFunc("GET /_emulator/portal/api/certificate", s.portalCertificate)
	s.mux.HandleFunc("PUT /_emulator/portal/api/certificate", s.portalCertificate)
	s.mux.HandleFunc("GET /_emulator/portal/api/tag", s.portalTag)
	s.mux.HandleFunc("PUT /_emulator/portal/api/tag", s.portalTag)
	s.mux.HandleFunc("GET /_emulator/portal/api/group", s.portalGroup)
	s.mux.HandleFunc("PUT /_emulator/portal/api/group", s.portalGroup)
	s.mux.HandleFunc("GET /_emulator/portal/api/subscription", s.portalSubscription)
	s.mux.HandleFunc("PUT /_emulator/portal/api/subscription", s.portalSubscription)
	s.mux.HandleFunc("GET /_emulator/portal/api/user", s.portalUser)
	s.mux.HandleFunc("PUT /_emulator/portal/api/user", s.portalUser)
	s.mux.HandleFunc("POST /_emulator/portal/api/faults", s.updateFault)
	s.mux.HandleFunc("GET /_emulator/portal/api/policy", s.portalPolicy)
	s.mux.HandleFunc("PUT /_emulator/portal/api/policy", s.portalPolicy)
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(strings.ToLower(r.URL.Path), "/subscriptions/") {
			s.ARM.ServeHTTP(w, r)
			return
		}
		s.Gateway.ServeHTTP(w, r)
	})
}

func (s *Server) portal(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(portalHTML))
}

func (s *Server) portalStatus(w http.ResponseWriter, _ *http.Request) {
	offset, frozen, now := s.Clock.State()
	services, _ := s.Store.ListServices()
	resources := make([]map[string]any, 0, len(services))
	for _, service := range services {
		apis, _ := s.Store.ListAPIs(service.ID())
		resources = append(resources, map[string]any{
			"id": service.ID(), "name": service.Name,
			"counts": map[string]int{
				"apis": len(apis), "apiVersionSets": countAPIVersionSets(s.Store, service.ID()),
				"namedValues": countNamedValues(s.Store, service.ID()), "backends": countBackends(s.Store, service.ID()),
				"caches":                 countCaches(s.Store, service.ID()),
				"identityProviders":      countIdentityProviders(s.Store, service.ID()),
				"openidConnectProviders": countOpenIDConnectProviders(s.Store, service.ID()),
				"authorizationServers":   countAuthorizationServers(s.Store, service.ID()),
				"documentations":         countDocumentations(s.Store, service.ID()),
				"certificates":           countCertificates(s.Store, service.ID()), "tags": countTags(s.Store, service.ID()),
				"groups": countGroups(s.Store, service.ID()), "users": countUsers(s.Store, service.ID()),
				"policyFragments": countPolicyFragments(s.Store, service.ID()), "products": countProducts(s.Store, service.ID()),
				"subscriptions": countSubscriptions(s.Store, service.ID()), "loggers": countLoggers(s.Store, service.ID()),
			},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service":   s.Cfg.DefaultService,
		"clock":     map[string]any{"offset": offset, "frozen": frozen, "now": now},
		"snapshot":  s.Gateway.SnapshotSummary(),
		"resources": resources,
		"faults":    s.Gateway.FaultsSnapshot(),
	})
}

func (s *Server) portalDiagnostics(w http.ResponseWriter, r *http.Request) {
	serviceID := strings.TrimSpace(r.URL.Query().Get("serviceId"))
	if serviceID == "" {
		serviceID = model.Service{SubscriptionID: defaultSubscription, ResourceGroup: defaultResourceGroup, Name: s.Cfg.DefaultService}.ID()
	}
	events, err := s.Store.ListDiagnosticEvents(serviceID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"serviceId": serviceID, "events": events})
}

func (s *Server) portalResource(w http.ResponseWriter, r *http.Request) {
	resourceID := strings.TrimSpace(r.URL.Query().Get("resourceId"))
	if resourceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "resourceId is required"})
		return
	}
	api, err := s.Store.GetAPI(resourceID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "resource not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if r.Method == http.MethodPut {
		var body struct {
			DisplayName          *string `json:"displayName"`
			Path                 *string `json:"path"`
			ServiceURL           *string `json:"serviceUrl"`
			SubscriptionRequired *bool   `json:"subscriptionRequired"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed JSON"})
			return
		}
		if body.DisplayName != nil {
			api.DisplayName = strings.TrimSpace(*body.DisplayName)
		}
		if body.Path != nil {
			api.Path = strings.Trim(*body.Path, "/")
		}
		if body.ServiceURL != nil {
			api.ServiceURL = strings.TrimSpace(*body.ServiceURL)
		}
		if body.SubscriptionRequired != nil {
			api.SubscriptionRequired = *body.SubscriptionRequired
		}
		if api.DisplayName == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "displayName cannot be empty"})
			return
		}
		api, err = s.portalUpsertAPI(api)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if err := s.Gateway.Activate(s.Store, s.Cfg.StrictPolicies); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": api.ID(), "name": api.Name, "displayName": api.DisplayName, "path": api.Path,
		"serviceUrl": api.ServiceURL, "subscriptionRequired": api.SubscriptionRequired, "etag": api.ETag,
	})
}

func (s *Server) portalProduct(w http.ResponseWriter, r *http.Request) {
	resourceID := strings.TrimSpace(r.URL.Query().Get("resourceId"))
	if resourceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "resourceId is required"})
		return
	}
	product, err := s.Store.GetProduct(resourceID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "product not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if r.Method == http.MethodPut {
		var body struct {
			DisplayName      *string `json:"displayName"`
			State            *string `json:"state"`
			ApprovalRequired *bool   `json:"approvalRequired"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed JSON"})
			return
		}
		if body.DisplayName != nil {
			product.DisplayName = strings.TrimSpace(*body.DisplayName)
		}
		if body.State != nil {
			product.State = strings.TrimSpace(*body.State)
		}
		if body.ApprovalRequired != nil {
			product.ApprovalRequired = *body.ApprovalRequired
		}
		if product.DisplayName == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "displayName cannot be empty"})
			return
		}
		product, err = s.portalUpsertProduct(product)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if err := s.Gateway.Activate(s.Store, s.Cfg.StrictPolicies); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": product.ID(), "name": product.Name, "displayName": product.DisplayName,
		"state": product.State, "approvalRequired": product.ApprovalRequired, "etag": product.ETag,
	})
}

func (s *Server) portalBackend(w http.ResponseWriter, r *http.Request) {
	resourceID := strings.TrimSpace(r.URL.Query().Get("resourceId"))
	if resourceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "resourceId is required"})
		return
	}
	backend, err := s.Store.GetBackend(resourceID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "backend not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if r.Method == http.MethodPut {
		var body struct {
			Title       *string `json:"title"`
			Description *string `json:"description"`
			URL         *string `json:"url"`
			Protocol    *string `json:"protocol"`
			ResourceID  *string `json:"resourceId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed JSON"})
			return
		}
		if body.Title != nil {
			backend.Title = strings.TrimSpace(*body.Title)
		}
		if body.Description != nil {
			backend.Description = *body.Description
		}
		if body.URL != nil {
			backend.URL = strings.TrimSpace(*body.URL)
		}
		if body.Protocol != nil {
			backend.Protocol = strings.TrimSpace(*body.Protocol)
		}
		if body.ResourceID != nil {
			backend.ResourceID = strings.TrimSpace(*body.ResourceID)
		}
		if backend.Title == "" || backend.URL == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "title and url are required"})
			return
		}
		backend, err = s.portalUpsertBackend(backend)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if err := s.Gateway.Activate(s.Store, s.Cfg.StrictPolicies); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": backend.ID(), "name": backend.Name, "title": backend.Title, "description": backend.Description,
		"url": backend.URL, "protocol": backend.Protocol, "resourceId": backend.ResourceID, "etag": backend.ETag,
	})
}

func (s *Server) portalNamedValue(w http.ResponseWriter, r *http.Request) {
	resourceID := strings.TrimSpace(r.URL.Query().Get("resourceId"))
	if resourceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "resourceId is required"})
		return
	}
	value, err := s.Store.GetNamedValue(resourceID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "named value not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if r.Method == http.MethodPut {
		var body struct {
			DisplayName *string  `json:"displayName"`
			Value       *string  `json:"value"`
			Tags        []string `json:"tags"`
			Secret      *bool    `json:"secret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed JSON"})
			return
		}
		if body.DisplayName != nil {
			value.DisplayName = strings.TrimSpace(*body.DisplayName)
		}
		if body.Value != nil {
			value.Value = *body.Value
		}
		if body.Tags != nil {
			value.Tags = append([]string(nil), body.Tags...)
		}
		if body.Secret != nil {
			value.Secret = *body.Secret
		}
		if value.DisplayName == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "displayName cannot be empty"})
			return
		}
		value, err = s.portalUpsertNamedValue(value)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if err := s.Gateway.Activate(s.Store, s.Cfg.StrictPolicies); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
	}
	result := map[string]any{"id": value.ID(), "name": value.Name, "displayName": value.DisplayName, "secret": value.Secret, "tags": value.Tags, "etag": value.ETag}
	if !value.Secret {
		result["value"] = value.Value
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) portalCertificate(w http.ResponseWriter, r *http.Request) {
	resourceID := strings.TrimSpace(r.URL.Query().Get("resourceId"))
	if resourceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "resourceId is required"})
		return
	}
	certificate, err := s.Store.GetCertificate(resourceID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "certificate not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if r.Method == http.MethodPut {
		var body struct {
			Subject            *string `json:"subject"`
			Thumbprint         *string `json:"thumbprint"`
			KeyVaultSecretID   *string `json:"keyVaultSecretId"`
			KeyVaultIdentityID *string `json:"keyVaultIdentityId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed JSON"})
			return
		}
		if body.Subject != nil {
			certificate.Subject = strings.TrimSpace(*body.Subject)
		}
		if body.Thumbprint != nil {
			certificate.Thumbprint = strings.TrimSpace(*body.Thumbprint)
		}
		if body.KeyVaultSecretID != nil {
			certificate.KeyVaultSecretID = strings.TrimSpace(*body.KeyVaultSecretID)
		}
		if body.KeyVaultIdentityID != nil {
			certificate.KeyVaultIdentityID = strings.TrimSpace(*body.KeyVaultIdentityID)
		}
		certificate, err = s.portalUpsertCertificate(certificate)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if err := s.Gateway.Activate(s.Store, s.Cfg.StrictPolicies); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": certificate.ID(), "name": certificate.Name, "subject": certificate.Subject,
		"thumbprint": certificate.Thumbprint, "expiration": certificate.Expiration, "keyVaultSecretId": certificate.KeyVaultSecretID,
		"keyVaultIdentityId": certificate.KeyVaultIdentityID, "hasData": len(certificate.Data) > 0, "etag": certificate.ETag,
	})
}

func (s *Server) portalTag(w http.ResponseWriter, r *http.Request) {
	resourceID := strings.TrimSpace(r.URL.Query().Get("resourceId"))
	if resourceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "resourceId is required"})
		return
	}
	tag, err := s.Store.GetTag(resourceID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "tag not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if r.Method == http.MethodPut {
		var body struct {
			DisplayName *string `json:"displayName"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed JSON"})
			return
		}
		if body.DisplayName != nil {
			tag.DisplayName = strings.TrimSpace(*body.DisplayName)
		}
		if tag.DisplayName == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "displayName cannot be empty"})
			return
		}
		tag, err = s.portalUpsertTag(tag)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if err := s.Gateway.Activate(s.Store, s.Cfg.StrictPolicies); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": tag.ID(), "name": tag.Name, "displayName": tag.DisplayName, "etag": tag.ETag})
}

func (s *Server) portalGroup(w http.ResponseWriter, r *http.Request) {
	resourceID := strings.TrimSpace(r.URL.Query().Get("resourceId"))
	if resourceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "resourceId is required"})
		return
	}
	group, err := s.Store.GetGroup(resourceID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "group not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if r.Method == http.MethodPut {
		var body struct {
			DisplayName *string `json:"displayName"`
			Description *string `json:"description"`
			Type        *string `json:"type"`
			ExternalID  *string `json:"externalId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed JSON"})
			return
		}
		if body.DisplayName != nil {
			group.DisplayName = strings.TrimSpace(*body.DisplayName)
		}
		if body.Description != nil {
			group.Description = *body.Description
		}
		if body.Type != nil {
			group.Type = strings.TrimSpace(*body.Type)
		}
		if body.ExternalID != nil {
			group.ExternalID = strings.TrimSpace(*body.ExternalID)
		}
		if group.DisplayName == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "displayName cannot be empty"})
			return
		}
		group, err = s.portalUpsertGroup(group)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if err := s.Gateway.Activate(s.Store, s.Cfg.StrictPolicies); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": group.ID(), "name": group.Name, "displayName": group.DisplayName, "description": group.Description, "type": group.Type, "externalId": group.ExternalID, "builtIn": group.BuiltIn, "etag": group.ETag})
}

func (s *Server) portalSubscription(w http.ResponseWriter, r *http.Request) {
	resourceID := strings.TrimSpace(r.URL.Query().Get("resourceId"))
	if resourceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "resourceId is required"})
		return
	}
	subscription, err := s.Store.GetSubscription(resourceID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "subscription not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if r.Method == http.MethodPut {
		var body struct {
			DisplayName *string `json:"displayName"`
			Scope       *string `json:"scope"`
			State       *string `json:"state"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed JSON"})
			return
		}
		if body.DisplayName != nil {
			subscription.DisplayName = strings.TrimSpace(*body.DisplayName)
		}
		if body.Scope != nil {
			subscription.Scope = strings.TrimSpace(*body.Scope)
		}
		if body.State != nil {
			subscription.State = strings.TrimSpace(*body.State)
		}
		if subscription.DisplayName == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "displayName cannot be empty"})
			return
		}
		subscription, err = s.portalUpsertSubscription(subscription)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if err := s.Gateway.Activate(s.Store, s.Cfg.StrictPolicies); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": subscription.ID(), "name": subscription.Name, "displayName": subscription.DisplayName, "scope": subscription.Scope, "state": subscription.State, "etag": subscription.ETag})
}

func (s *Server) portalUser(w http.ResponseWriter, r *http.Request) {
	resourceID := strings.TrimSpace(r.URL.Query().Get("resourceId"))
	if resourceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "resourceId is required"})
		return
	}
	user, err := s.Store.GetUser(resourceID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "user not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if r.Method == http.MethodPut {
		var body struct {
			FirstName *string `json:"firstName"`
			LastName  *string `json:"lastName"`
			Email     *string `json:"email"`
			State     *string `json:"state"`
			Note      *string `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed JSON"})
			return
		}
		if body.FirstName != nil {
			user.FirstName = strings.TrimSpace(*body.FirstName)
		}
		if body.LastName != nil {
			user.LastName = strings.TrimSpace(*body.LastName)
		}
		if body.Email != nil {
			user.Email = strings.TrimSpace(*body.Email)
		}
		if body.State != nil {
			user.State = strings.TrimSpace(*body.State)
		}
		if body.Note != nil {
			user.Note = *body.Note
		}
		if user.Email == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "email cannot be empty"})
			return
		}
		user, err = s.portalUpsertUser(user)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if err := s.Gateway.Activate(s.Store, s.Cfg.StrictPolicies); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": user.ID(), "name": user.Name, "firstName": user.FirstName, "lastName": user.LastName, "email": user.Email, "state": user.State, "note": user.Note, "identities": user.Identities, "etag": user.ETag})
}

func countAPIVersionSets(st *store.Store, id string) int {
	v, _ := st.ListAPIVersionSets(id)
	return len(v)
}
func countNamedValues(st *store.Store, id string) int { v, _ := st.ListNamedValues(id); return len(v) }
func countBackends(st *store.Store, id string) int    { v, _ := st.ListBackends(id); return len(v) }
func countCaches(st *store.Store, id string) int      { v, _ := st.ListCaches(id); return len(v) }
func countIdentityProviders(st *store.Store, id string) int {
	v, _ := st.ListIdentityProviders(id)
	return len(v)
}
func countOpenIDConnectProviders(st *store.Store, id string) int {
	v, _ := st.ListOpenIDConnectProviders(id)
	return len(v)
}
func countAuthorizationServers(st *store.Store, id string) int {
	v, _ := st.ListAuthorizationServers(id)
	return len(v)
}
func countDocumentations(st *store.Store, id string) int {
	v, _ := st.ListDocumentations(id)
	return len(v)
}
func countCertificates(st *store.Store, id string) int {
	v, _ := st.ListCertificates(id)
	return len(v)
}
func countTags(st *store.Store, id string) int   { v, _ := st.ListTags(id); return len(v) }
func countGroups(st *store.Store, id string) int { v, _ := st.ListGroups(id); return len(v) }
func countUsers(st *store.Store, id string) int  { v, _ := st.ListUsers(id); return len(v) }
func countPolicyFragments(st *store.Store, id string) int {
	v, _ := st.ListPolicyFragments(id)
	return len(v)
}
func countProducts(st *store.Store, id string) int { v, _ := st.ListProducts(id); return len(v) }
func countSubscriptions(st *store.Store, id string) int {
	v, _ := st.ListSubscriptions(id)
	return len(v)
}
func countLoggers(st *store.Store, id string) int { v, _ := st.ListLoggers(id); return len(v) }

func (s *Server) updateFault(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Service   string `json:"service"`
		Backend   string `json:"backend"`
		Status    int    `json:"status"`
		DelayMS   int    `json:"delayMs"`
		Error     bool   `json:"error"`
		Remaining int    `json:"remaining"`
		Body      string `json:"body"`
		Clear     bool   `json:"clear"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Service) == "" || strings.TrimSpace(body.Backend) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "service and backend are required"})
		return
	}
	fault := gateway.Fault{Status: body.Status, DelayMS: body.DelayMS, Error: body.Error, Remaining: body.Remaining, Body: body.Body}
	if body.Clear {
		fault = gateway.Fault{}
	}
	s.Gateway.SetFault(body.Service, body.Backend, fault)
	writeJSON(w, http.StatusOK, s.Gateway.FaultsSnapshot())
}

func (s *Server) portalPolicy(w http.ResponseWriter, r *http.Request) {
	scopeID := strings.TrimSpace(r.URL.Query().Get("scopeId"))
	if scopeID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "scopeId is required"})
		return
	}
	if r.Method == http.MethodGet {
		value, err := s.Store.GetPolicy(scopeID)
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "policy not found"})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, value)
		return
	}
	var body struct {
		Format string `json:"format"`
		Value  string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Value) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "format and value are required"})
		return
	}
	if _, err := policy.Compile(body.Value, s.Cfg.StrictPolicies); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	value, err := s.Store.UpsertPolicy(model.Policy{ScopeID: scopeID, Format: body.Format, Value: body.Value})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if err := s.Gateway.Activate(s.Store, s.Cfg.StrictPolicies); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, value)
}

const portalHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>APIM Emulator Operator</title>
<style>body{font:15px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#17202a;background:#f6f8fa}main{background:#fff;border:1px solid #d0d7de;padding:1.25rem;border-radius:8px}h1{margin-top:0}h2{font-size:1rem;margin:1.5rem 0 .5rem}pre{background:#f6f8fa;padding:1rem;overflow:auto}button{padding:.55rem .8rem;border:1px solid #8c959f;border-radius:6px;background:#fff;cursor:pointer}table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{text-align:left;border-bottom:1px solid #d8dee4;padding:.45rem}#error{color:#b42318}</style></head>
<body><main><h1>Azure APIM Emulator</h1><p id="summary">Loading runtime state...</p><button id="refresh">Refresh</button><p id="error" role="alert"></p><h2>Resources</h2><table><thead><tr><th>Service</th><th>Resource</th><th>Count</th></tr></thead><tbody id="resources"></tbody></table><h2>Diagnostic Events</h2><pre id="diagnostics">Loading...</pre></main>
<script>
async function get(path){const r=await fetch(path);if(!r.ok)throw new Error(await r.text());return r.json()}
async function load(){document.querySelector('#error').textContent='';try{const [status,diagnostics]=await Promise.all([get('/_emulator/portal/api/status'),get('/_emulator/portal/api/diagnostics')]);document.querySelector('#summary').textContent=status.service+' | clock '+status.clock.now;const rows=[];for(const service of status.resources||[]){for(const [name,count] of Object.entries(service.counts||{})){rows.push('<tr><td>'+service.name+'</td><td>'+name+'</td><td>'+count+'</td></tr>')}}document.querySelector('#resources').innerHTML=rows.join('');document.querySelector('#diagnostics').textContent=JSON.stringify(diagnostics.events||[],null,2)}catch(error){document.querySelector('#error').textContent='Unable to load operator state: '+error.message}}
document.querySelector('#refresh').addEventListener('click',load);load();</script></body></html>`

func (s *Server) updateClock(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Advance *int64 `json:"advance"`
		Offset  *int64 `json:"offset"`
		Freeze  *bool  `json:"freeze"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed JSON"})
		return
	}
	if body.Offset != nil {
		s.Clock.SetOffset(*body.Offset)
	}
	if body.Advance != nil {
		s.Clock.Advance(*body.Advance)
	}
	if body.Freeze != nil {
		if *body.Freeze {
			s.Clock.Freeze()
		} else {
			s.Clock.Unfreeze()
		}
	}
	offset, frozen, now := s.Clock.State()
	writeJSON(w, http.StatusOK, map[string]any{"offset": offset, "frozen": frozen, "now": now})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// collapseSlashes reduces runs of `/` to one. Only the path is touched; a
// doubled slash inside a query value is the caller's data, not routing.
func collapseSlashes(path string) string {
	if !strings.Contains(path, "//") {
		return path
	}
	var builder strings.Builder
	previousSlash := false
	for _, r := range path {
		if r == '/' {
			if previousSlash {
				continue
			}
			previousSlash = true
		} else {
			previousSlash = false
		}
		builder.WriteRune(r)
	}
	return builder.String()
}
