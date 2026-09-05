// Package arm implements the Microsoft.ApiManagement management surface.
package arm

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/calvinchengx/azure-apim-emulator/internal/auth"
	certutil "github.com/calvinchengx/azure-apim-emulator/internal/certificate"
	"github.com/calvinchengx/azure-apim-emulator/internal/keyvault"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	openapic "github.com/calvinchengx/azure-apim-emulator/internal/openapi"
	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
	soapc "github.com/calvinchengx/azure-apim-emulator/internal/soap"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

var supportedVersions = map[string]bool{"2021-08-01": true, "2022-08-01": true, "2024-05-01": true}

// authorizationVersions are Microsoft.Authorization's own API versions, which
// are NOT APIM's. A client managing role assignments sends the version its own
// provider publishes, so validating it against the APIM list rejects every such
// request before it is even routed.
var authorizationVersions = map[string]bool{
	"2015-07-01": true, "2018-01-01-preview": true, "2020-04-01-preview": true,
	"2020-08-01-preview": true, "2020-10-01-preview": true, "2022-04-01": true,
}
var namedValueDisplayName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
var documentationName = regexp.MustCompile(`^[^*#&+:<>?]+$`)

// Handler serves the P0 APIM ARM resources.
type Handler struct {
	Store    *store.Store
	Auth     auth.RequestValidator
	Activate func() error
	// EnforceRBAC evaluates role assignments before each request. Off by
	// default, which is what every existing caller assumes.
	EnforceRBAC bool
	// EnforceTiers refuses capabilities the service's SKU does not have. Off
	// by default: see internal/config for why, and for why that default is
	// itself a divergence rather than a neutral choice.
	EnforceTiers bool
	// RBACOwner holds Owner at subscription scope while enforcement is on, so
	// the first assignment can be created at all.
	RBACOwner      string
	ValidatePolicy func(string) error
	// ValidateResolverPolicy validates a GraphQL resolver's <http-data-source>.
	ValidateResolverPolicy func(string) error
	// LoginLink and ConfirmConsent are the credential-manager consent handshake.
	// Supplied by the server, which owns the OAuth2 client; the ARM handler
	// must not perform token exchanges itself.
	LoginLink      func(providerID, authorizationID, redirectURI string) (string, error)
	ConfirmConsent func(providerID, authorizationID, code string) error
	ImportClient   *http.Client
	ExportKey      []byte
	Secrets        keyvault.Retriever
	AcquireToken   func(context.Context, string, string) (string, error)
	// KeyVaultClient overrides ImportClient for the vault leg only, so trusting
	// a sibling emulator's certificate does not loosen API imports.
	KeyVaultClient       *http.Client
	IdentityClientID     string
	IdentityClientSecret string
	mutationMu           sync.Mutex
}

// ServeHTTP routes APIM provider requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := store.NewOpaqueID()
	w.Header().Set("x-ms-request-id", requestID)
	w.Header().Set("x-ms-correlation-request-id", requestID)
	if r.URL.Query().Get("export") == "download" {
		h.apiExportDownload(w, r)
		return
	}
	principal, err := h.Auth.ValidateRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "AuthenticationFailed", err.Error(), "")
		return
	}
	version := r.URL.Query().Get("api-version")
	if authorization, ok := parseAuthorization(r.URL.Path); ok {
		if !authorizationVersions[version] {
			writeError(w, http.StatusBadRequest, "InvalidApiVersionParameter", "The api-version query parameter is invalid or unsupported.", "api-version")
			return
		}
		if !h.authorize(w, r, principal, authorization.Scope) {
			return
		}
		h.authorization(w, r, authorization)
		return
	}
	if !supportedVersions[version] {
		writeError(w, http.StatusBadRequest, "InvalidApiVersionParameter", "The api-version query parameter is invalid or unsupported.", "api-version")
		return
	}
	// The subscription-wide SKU catalogue is a sibling of `service`, not a
	// child of one, so it is answered before the service parser runs.
	if location, ok := parseProviderSKUs(split(r.URL.Path)); ok {
		h.providerSKURoute(w, r, location)
		return
	}
	parsed, ok := parse(split(r.URL.Path))
	if !ok {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested resource was not found.", r.URL.Path)
		return
	}
	if !h.authorize(w, r, principal, r.URL.Path) {
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
		h.mutationMu.Lock()
		defer h.mutationMu.Unlock()
	}
	if h.handleConditionalRequest(w, r, parsed) {
		return
	}
	h.routeRequest(w, r, parsed)
}

func (h *Handler) routeRequest(w http.ResponseWriter, r *http.Request, parsed route) {
	if h.handleCollectionRequest(w, r, parsed) {
		return
	}
	h.dispatch(w, r, parsed)
}

func (h *Handler) dispatch(w http.ResponseWriter, r *http.Request, parsed route) {
	if len(parsed.Tail) == 0 {
		h.service(w, r, parsed)
		return
	}
	// A workspace segment is peeled off and recorded as the SCOPE, then
	// dispatch continues on the remaining path. That is the whole mechanism:
	// every family below serves workspace-scoped requests without knowing
	// workspaces exist, because the only thing that changed is the parent ID
	// their resources hang off.
	if equal(parsed.Tail[0], "workspaces") && parsed.Workspace == "" {
		if !h.requireCapability(w, parsed.service().ID(), capabilityWorkspaces) {
			return
		}
		if len(parsed.Tail) == 1 {
			h.workspaceCollection(w, r, parsed)
			return
		}
		if len(parsed.Tail) == 2 {
			h.workspaceResource(w, r, parsed, model.Workspace{ServiceID: parsed.service().ID(), Name: parsed.Tail[1]})
			return
		}
		// No capability check here: the one above already ran for this same
		// service and capability, and nothing between them writes to the store,
		// so a second call can only ever agree with the first. It also cost a
		// redundant service read on every workspace-scoped nested request.
		nested := parsed
		nested.Workspace, nested.Tail = parsed.Tail[1], parsed.Tail[2:]
		// The workspace must exist before anything can be parented to it,
		// otherwise a typo in the path would silently create resources in a
		// scope nobody can address.
		if err := h.requireScope(nested); err != nil {
			h.storeError(w, err, nested.scopeID())
			return
		}
		if serviceOnlyFamilies[strings.ToLower(nested.Tail[0])] {
			writeError(w, http.StatusNotFound, "ResourceNotFound",
				nested.Tail[0]+" is not a workspace-scoped resource in Azure; it belongs to the service.",
				nested.scopeID()+"/"+nested.Tail[0])
			return
		}
		h.dispatch(w, r, nested)
		return
	}
	switch parsed.Tail[0] {
	case "apis":
		h.api(w, r, parsed)
	case "apiVersionSets":
		h.apiVersionSet(w, r, parsed)
	case "namedValues":
		h.namedValue(w, r, parsed)
	case "backends":
		h.backend(w, r, parsed)
	case "caches":
		h.cache(w, r, parsed)
	case "identityProviders":
		h.identityProvider(w, r, parsed)
	case "openidConnectProviders":
		h.openIDConnectProvider(w, r, parsed)
	case "authorizationProviders":
		// Credential manager. Note the neighbour below: authorizationServers is
		// a DIFFERENT resource (the portal console's OAuth2 server), and the
		// two are one word apart.
		h.authorizationProviderRoute(w, r, parsed)
	case "authorizationServers":
		h.authorizationServer(w, r, parsed)
	case "gateways":
		h.gatewayRoute(w, r, parsed)
	case "skus":
		h.skuRoute(w, r, parsed)
	case "regions":
		h.regionRoute(w, r, parsed)
	case "privateEndpointConnections":
		h.privateEndpointConnectionRoute(w, r, parsed)
	case "privateLinkResources":
		h.privateLinkResourceRoute(w, r, parsed)
	case "networkstatus":
		h.networkStatusRoute(w, r, parsed, "")
	case "outboundNetworkDependenciesEndpoints":
		h.outboundNetworkDependenciesRoute(w, r, parsed)
	case "locations":
		// `locations/{name}/networkstatus` is the per-region form. It is the
		// only thing under `locations`, so anything else there is a 404 rather
		// than a hint that more exists.
		if len(parsed.Tail) == 3 && equal(parsed.Tail[2], "networkstatus") {
			h.networkStatusRoute(w, r, parsed, parsed.Tail[1])
			return
		}
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested APIM resource is not implemented in the P0 surface.", r.URL.Path)
	case "documentations":
		h.documentation(w, r, parsed)
	case "certificates":
		h.certificate(w, r, parsed)
	case "tags":
		h.tag(w, r, parsed)
	case "groups":
		h.group(w, r, parsed)
	case "users":
		h.user(w, r, parsed)
	case "policyFragments":
		h.policyFragment(w, r, parsed)
	case "loggers":
		h.logger(w, r, parsed)
	case "diagnostics":
		h.diagnostic(w, r, parsed, parsed.scopeID(), 1)
	case "products":
		h.product(w, r, parsed)
	case "subscriptions":
		h.subscription(w, r, parsed)
	case "policies":
		if len(parsed.Tail) == 2 && equal(parsed.Tail[1], "policy") {
			// The parent must exist before a policy can hang off it, and which
			// parent that is depends on the scope: a workspace policy belongs
			// to the workspace, not to the service.
			if err := h.requireScope(parsed); err != nil {
				h.storeError(w, err, parsed.scopeID())
				return
			}
			armType := "Microsoft.ApiManagement/service/policies"
			if parsed.Workspace != "" {
				armType = "Microsoft.ApiManagement/service/workspaces/policies"
			}
			h.policyResource(w, r, parsed.scopeID(), armType)
			return
		}
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested APIM resource is not implemented in the P0 surface.", r.URL.Path)
	default:
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested APIM resource is not implemented in the P0 surface.", r.URL.Path)
	}
}

// serviceOnlyFamilies are the resource families Azure exposes at SERVICE scope
// only, so a `/workspaces/{id}/<family>` path must 404 rather than be served.
//
// The peeling above is deliberately family-blind -- that is what let workspaces
// ship without per-family work -- and this is the price of that design: a
// family Azure does NOT put in a workspace is otherwise happily created there,
// parented to the workspace, retrievable, and absent from Azure. That is the
// leniency direction, which has no local symptom: the flow works here and 404s
// the first time it runs against a real tenant.
//
// The list is derived from `@azure/arm-apimanagement@10.0.0`, which publishes a
// separate `Workspace*` operation group for every family Azure genuinely scopes
// to a workspace (WorkspaceApi, WorkspaceBackend, WorkspaceCertificate,
// WorkspaceNamedValue, WorkspaceProduct, WorkspaceSubscription, WorkspaceTag,
// WorkspaceGroup, WorkspaceLogger, WorkspaceDiagnostic, WorkspacePolicy,
// WorkspacePolicyFragment, WorkspaceApiVersionSet, WorkspaceGlobalSchema,
// WorkspaceNotification). A family below has no such group.
//
// `users` is the one worth explaining: there IS a `WorkspaceGroupUser`, but it
// is a MEMBERSHIP link, not user CRUD. Users are a service-level directory that
// a workspace group draws members from, so the directory itself is not
// workspace-scoped.
//
// Being a snapshot of one SDK version, this is evidence rather than proof: if a
// later SDK adds a Workspace* group for one of these, delete the row.
var serviceOnlyFamilies = map[string]bool{
	"caches":                 true,
	"identityproviders":      true,
	"openidconnectproviders": true,
	"authorizationproviders": true,
	"authorizationservers":   true,
	"documentations":         true,
	"gateways":               true,
	"users":                  true,
	// Networking belongs to the service, never to a workspace inside it.
	"privateendpointconnections":           true,
	"privatelinkresources":                 true,
	"networkstatus":                        true,
	"outboundnetworkdependenciesendpoints": true,
	"locations":                            true,
	"skus":                                 true,
	"regions":                              true,
}

type route struct {
	SubscriptionID, ResourceGroup, ServiceName string
	// Workspace is set when the path carried a `/workspaces/{id}` segment. It
	// is a SCOPE, not a resource kind: every family Azure exposes under a
	// workspace is the same family it exposes under the service, parented
	// differently. Modelling it as a scope is what lets one set of handlers
	// serve both, and the store's exact parent matching is what keeps the two
	// sets of resources from leaking into each other's listings.
	Workspace string
	Tail      []string
}

// service is the ARM service this route addresses.
func (rt route) service() model.Service {
	return model.Service{SubscriptionID: rt.SubscriptionID, ResourceGroup: rt.ResourceGroup, Name: rt.ServiceName}
}

// scopeID is the parent every resource under this route belongs to: the
// service, or a workspace within it.
func (rt route) scopeID() string {
	if rt.Workspace == "" {
		return rt.service().ID()
	}
	return rt.service().ID() + "/workspaces/" + rt.Workspace
}

type servicePayload struct {
	Location string `json:"location"`
	SKU      struct {
		Name     string `json:"name"`
		Capacity int    `json:"capacity"`
	} `json:"sku"`
	Properties struct {
		PublisherName  string `json:"publisherName"`
		PublisherEmail string `json:"publisherEmail"`
	} `json:"properties"`
}

// parseProviderSKUs recognises the subscription-scoped SKU catalogue,
// `/subscriptions/{id}/providers/Microsoft.ApiManagement/skus`, and reports the
// location to advertise them in.
func parseProviderSKUs(parts []string) (string, bool) {
	if len(parts) == 5 && equal(parts[0], "subscriptions") && equal(parts[2], "providers") &&
		equal(parts[3], "Microsoft.ApiManagement") && equal(parts[4], "skus") {
		return "local", true
	}
	return "", false
}

func parse(parts []string) (route, bool) {
	if len(parts) >= 5 && equal(parts[0], "subscriptions") && equal(parts[2], "providers") &&
		equal(parts[3], "Microsoft.ApiManagement") && equal(parts[4], "service") {
		result := route{SubscriptionID: parts[1]}
		if len(parts) > 5 {
			result.ServiceName, result.Tail = parts[5], parts[6:]
		}
		return result, true
	}
	if len(parts) >= 7 && equal(parts[0], "subscriptions") && equal(parts[2], "resourceGroups") &&
		equal(parts[4], "providers") && equal(parts[5], "Microsoft.ApiManagement") && equal(parts[6], "service") {
		result := route{SubscriptionID: parts[1], ResourceGroup: parts[3]}
		if len(parts) > 7 {
			result.ServiceName, result.Tail = parts[7], parts[8:]
		}
		return result, true
	}
	return route{}, false
}

func (h *Handler) service(w http.ResponseWriter, r *http.Request, rt route) {
	if rt.ServiceName == "" {
		h.listServices(w, r, rt)
		return
	}
	value := model.Service{SubscriptionID: rt.SubscriptionID, ResourceGroup: rt.ResourceGroup, Name: rt.ServiceName}
	switch r.Method {
	case http.MethodGet:
		got, err := h.Store.GetService(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		writeResource(w, http.StatusOK, serviceWire(got), got.ETag)
	case http.MethodPut:
		var body servicePayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if body.Location == "" || body.Properties.PublisherName == "" || body.Properties.PublisherEmail == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "location, properties.publisherName, and properties.publisherEmail are required.", "properties")
			return
		}
		// A tier is not just a price: it decides how far the service scales and
		// which capabilities exist at all. Validating here is what stops a
		// caller building a topology locally that Azure refuses outright.
		serviceTier, message := validateSKU(body.SKU.Name, body.SKU.Capacity)
		if message != "" {
			writeError(w, http.StatusBadRequest, "ValidationError", message, "sku")
			return
		}
		if message := validateAdditionalLocations(document, serviceTier); message != "" {
			writeError(w, http.StatusBadRequest, "ValidationError", message, "properties.additionalLocations")
			return
		}
		projectAdditionalLocations(document, rt.ServiceName)
		_, existingErr := h.Store.GetService(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		value.Location, value.SKUName, value.SKUCapacity = body.Location, body.SKU.Name, body.SKU.Capacity
		value.PublisherName, value.PublisherEmail, value.Document = body.Properties.PublisherName, body.Properties.PublisherEmail, document
		// A hostname configuration carries a write-only PFX and read-only facts
		// about it in one object. Resolving here, on the way in, is what lets
		// the secret be dropped before it is ever stored.
		resolveHostnameCertificates(value.Document, time.Now().UTC())
		// No defaulting: validateSKU above refuses an absent or unknown tier, so
		// a service reaching this point named one. Defaulting here would have
		// been dead code, and worse, would have disagreed with the validation
		// about what an empty sku means.
		got, err := h.Store.UpsertService(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		w.Header().Set("Azure-AsyncOperation", absolute(r, "/_emulator/arm/operations/"+store.NewOpaqueID()+"?api-version="+r.URL.Query().Get("api-version")))
		status := http.StatusCreated
		if existingErr == nil {
			status = http.StatusOK
		}
		writeResource(w, status, serviceWire(got), got.ETag)
	case http.MethodPatch:
		got, err := h.Store.GetService(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		var body struct {
			Location string `json:"location"`
			SKU      struct {
				Name     *string `json:"name"`
				Capacity *int    `json:"capacity"`
			} `json:"sku"`
			Properties struct {
				PublisherName  *string `json:"publisherName"`
				PublisherEmail *string `json:"publisherEmail"`
			} `json:"properties"`
		}
		var patch map[string]any
		if err := decodeDocument(r, &body, &patch); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if got.Document == nil {
			got.Document = serviceWire(got)
		}
		mergeObject(got.Document, patch)
		if body.SKU.Name != nil {
			got.SKUName = *body.SKU.Name
		}
		if body.SKU.Capacity != nil {
			got.SKUCapacity = *body.SKU.Capacity
		}
		if body.Properties.PublisherName != nil {
			got.PublisherName = *body.Properties.PublisherName
		}
		if body.Properties.PublisherEmail != nil {
			got.PublisherEmail = *body.Properties.PublisherEmail
		}
		got, err = h.Store.UpsertService(got)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		writeResource(w, http.StatusOK, serviceWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteService(value.ID()); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) listServices(w http.ResponseWriter, r *http.Request, rt route) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	services, err := h.Store.ListServices()
	if err != nil {
		h.storeError(w, err, "")
		return
	}
	values := make([]map[string]any, 0)
	for _, service := range services {
		if !equal(service.SubscriptionID, rt.SubscriptionID) || (rt.ResourceGroup != "" && !equal(service.ResourceGroup, rt.ResourceGroup)) {
			continue
		}
		values = append(values, serviceWire(service))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": values})
}

func (h *Handler) api(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListAPIs(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, apiWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources})
		return
	}
	api := model.API{ServiceID: scope, Name: rt.Tail[1]}
	if len(rt.Tail) == 2 {
		h.apiResource(w, r, api)
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "operations") {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListOperations(api.ID())
		if err != nil {
			h.storeError(w, err, api.ID())
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, operationWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources})
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "schemas") {
		h.apiSchemaCollection(w, r, api)
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "resolvers") {
		h.apiResolverCollection(w, r, api)
		return
	}
	if len(rt.Tail) >= 3 && equal(rt.Tail[2], "diagnostics") {
		if _, err := h.Store.GetAPI(api.ID()); err != nil {
			h.storeError(w, err, api.ID())
			return
		}
		h.diagnostic(w, r, rt, api.ID(), 3)
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "tags") {
		if _, err := h.Store.GetAPI(api.ID()); err != nil {
			h.storeError(w, err, api.ID())
			return
		}
		h.resourceTagCollection(w, r, api.ID())
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "revisions") {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListAPIRevisions(scope, api.Name)
		if err != nil {
			h.storeError(w, err, api.ID())
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, apiRevisionWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "releases") {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListAPIReleases(api.ID())
		if err != nil {
			h.storeError(w, err, api.ID())
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, apiReleaseWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "operations") {
		h.operationResource(w, r, model.Operation{APIID: api.ID(), Name: rt.Tail[3]})
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "schemas") {
		h.apiSchemaResource(w, r, model.APISchema{APIID: api.ID(), Name: rt.Tail[3]})
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "resolvers") {
		h.apiResolverResource(w, r, model.APIResolver{APIID: api.ID(), Name: rt.Tail[3]})
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "tags") {
		if _, err := h.Store.GetAPI(api.ID()); err != nil {
			h.storeError(w, err, api.ID())
			return
		}
		h.resourceTag(w, r, scope, api.ID(), rt.Tail[3])
		return
	}
	if len(rt.Tail) == 5 && equal(rt.Tail[2], "operations") && equal(rt.Tail[4], "tags") {
		operationID := api.ID() + "/operations/" + rt.Tail[3]
		if _, err := h.Store.GetOperation(operationID); err != nil {
			h.storeError(w, err, operationID)
			return
		}
		h.resourceTagCollection(w, r, operationID)
		return
	}
	if len(rt.Tail) == 6 && equal(rt.Tail[2], "operations") && equal(rt.Tail[4], "tags") {
		operationID := api.ID() + "/operations/" + rt.Tail[3]
		if _, err := h.Store.GetOperation(operationID); err != nil {
			h.storeError(w, err, operationID)
			return
		}
		h.resourceTag(w, r, scope, operationID, rt.Tail[5])
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "releases") {
		h.apiReleaseResource(w, r, model.APIRelease{APIID: api.ID(), Name: rt.Tail[3]})
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "policies") && equal(rt.Tail[3], "policy") {
		h.policyResource(w, r, api.ID(), "Microsoft.ApiManagement/service/apis/policies")
		return
	}
	if len(rt.Tail) == 6 && equal(rt.Tail[2], "resolvers") && equal(rt.Tail[4], "policies") && equal(rt.Tail[5], "policy") {
		resolverID := api.ID() + "/resolvers/" + rt.Tail[3]
		if _, err := h.Store.GetAPIResolver(resolverID); err != nil {
			h.storeError(w, err, resolverID)
			return
		}
		h.policyResource(w, r, resolverID, "Microsoft.ApiManagement/service/apis/resolvers/policies")
		return
	}
	if len(rt.Tail) == 6 && equal(rt.Tail[2], "operations") && equal(rt.Tail[4], "policies") && equal(rt.Tail[5], "policy") {
		operationID := api.ID() + "/operations/" + rt.Tail[3]
		if _, err := h.Store.GetOperation(operationID); err != nil {
			h.storeError(w, err, operationID)
			return
		}
		h.policyResource(w, r, operationID, "Microsoft.ApiManagement/service/apis/operations/policies")
		return
	}
	writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested API resource was not found.", r.URL.Path)
}

func (h *Handler) tag(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListTags(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, tagWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if (len(rt.Tail) == 3 || len(rt.Tail) == 4) &&
		isLinkSegment(rt.Tail[2], "apiLinks", "operationLinks", "productLinks") {
		tag := model.Tag{ServiceID: scope, Name: rt.Tail[1]}
		if _, err := h.Store.GetTag(tag.ID()); err != nil {
			h.storeError(w, err, tag.ID())
			return
		}
		surface, err := h.tagLinkSurface(tag, rt.Tail[2])
		if err != nil {
			h.storeError(w, err, tag.ID())
			return
		}
		surface.armType = linkType(rt.Workspace != "", "tags", rt.Tail[2])
		name := ""
		if len(rt.Tail) == 4 {
			name = rt.Tail[3]
		}
		h.linkRoute(w, r, surface, name)
		return
	}
	if len(rt.Tail) != 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested tag resource was not found.", r.URL.Path)
		return
	}
	value := model.Tag{ServiceID: scope, Name: rt.Tail[1]}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetTag(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, tagWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetTag(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, value.ID())
				return
			}
			value = existing
		}
		var body struct {
			Properties struct {
				DisplayName *string `json:"displayName"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = tagWire(value)
			}
			mergeObject(value.Document, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		if body.Properties.DisplayName != nil {
			value.DisplayName = *body.Properties.DisplayName
		}
		if strings.TrimSpace(value.DisplayName) == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "displayName is required.", "properties.displayName")
			return
		}
		got, err := h.Store.UpsertTag(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, tagWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteTag(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) resourceTagCollection(w http.ResponseWriter, r *http.Request, resourceID string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	values, err := h.Store.ListResourceTags(resourceID)
	if err != nil {
		h.storeError(w, err, resourceID)
		return
	}
	resources := make([]map[string]any, 0, len(values))
	for _, value := range values {
		resources = append(resources, tagWire(value))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
}

func (h *Handler) resourceTag(w http.ResponseWriter, r *http.Request, serviceID, resourceID, tagName string) {
	tag := model.Tag{ServiceID: serviceID, Name: tagName}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetResourceTag(resourceID, tag.ID())
		if err != nil {
			h.storeError(w, err, tag.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, tagWire(got), got.ETag)
	case http.MethodPut:
		got, err := h.Store.GetTag(tag.ID())
		if err != nil {
			h.storeError(w, err, tag.ID())
			return
		}
		_, existingErr := h.Store.GetResourceTag(resourceID, tag.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, tag.ID())
			return
		}
		if err := h.Store.AssignTag(resourceID, tag.ID()); err != nil {
			h.storeError(w, err, tag.ID())
			return
		}
		status := http.StatusOK
		if errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, tagWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DetachTag(resourceID, tag.ID()); err != nil {
			h.storeError(w, err, tag.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) group(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListGroups(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, groupWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) >= 3 && equal(rt.Tail[2], "users") {
		group := model.Group{ServiceID: scope, Name: rt.Tail[1]}
		if _, err := h.Store.GetGroup(group.ID()); err != nil {
			h.storeError(w, err, group.ID())
			return
		}
		if len(rt.Tail) == 3 {
			if r.Method != http.MethodGet {
				methodNotAllowed(w)
				return
			}
			values, err := h.Store.ListGroupUsers(group.ID())
			if err != nil {
				h.storeError(w, err, group.ID())
				return
			}
			resources := make([]map[string]any, 0, len(values))
			for _, value := range values {
				resources = append(resources, userWire(value))
			}
			writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
			return
		}
		if len(rt.Tail) == 4 {
			// The GROUP is scoped, the MEMBER is not: a workspace group draws
			// its members from the service's user directory, which is why Azure
			// has WorkspaceGroupUser but no WorkspaceUser. Resolving the user at
			// the workspace scope instead would make a workspace group
			// unfillable, because no user exists at that scope to name.
			//
			// This is the only cross-family link of that shape in the emulator
			// today, and the shape is worth recognising before writing the next
			// one: a workspace-scoped PARENT resolving a child from a family in
			// serviceOnlyFamilies must resolve it at the SERVICE. Notifications
			// are where it recurs — the SDK has WorkspaceNotification and
			// WorkspaceNotificationRecipientUser — so if that family is ever
			// implemented, its recipientUsers is this line again.
			h.groupUser(w, r, group, model.User{ServiceID: rt.service().ID(), Name: rt.Tail[3]})
			return
		}
	}
	if len(rt.Tail) != 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested group resource was not found.", r.URL.Path)
		return
	}
	value := model.Group{ServiceID: scope, Name: rt.Tail[1], Type: "custom"}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetGroup(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, groupWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetGroup(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, value.ID())
				return
			}
			value = existing
		}
		var body struct {
			Properties struct {
				DisplayName *string `json:"displayName"`
				Description *string `json:"description"`
				Type        *string `json:"type"`
				ExternalID  *string `json:"externalId"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = groupWire(value)
			}
			mergeObject(value.Document, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		if body.Properties.DisplayName != nil {
			value.DisplayName = *body.Properties.DisplayName
		}
		if body.Properties.Description != nil {
			value.Description = *body.Properties.Description
		}
		if body.Properties.Type != nil {
			value.Type = *body.Properties.Type
		}
		if body.Properties.ExternalID != nil {
			value.ExternalID = *body.Properties.ExternalID
		}
		properties, _ := document["properties"].(map[string]any)
		if field, present := properties["description"]; present && field == nil {
			value.Description = ""
		}
		if field, present := properties["externalId"]; present && field == nil {
			value.ExternalID = ""
		}
		if strings.TrimSpace(value.DisplayName) == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "displayName is required.", "properties.displayName")
			return
		}
		if value.Type != "custom" && value.Type != "external" && value.Type != "system" {
			writeError(w, http.StatusBadRequest, "ValidationError", "type must be custom, external, or system.", "properties.type")
			return
		}
		if value.Type == "system" && !value.BuiltIn {
			writeError(w, http.StatusBadRequest, "ValidationError", "system groups are managed by the service.", "properties.type")
			return
		}
		if value.Type == "external" && strings.TrimSpace(value.ExternalID) == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "externalId is required for external groups.", "properties.externalId")
			return
		}
		got, err := h.Store.UpsertGroup(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, groupWire(got), got.ETag)
	case http.MethodDelete:
		got, err := h.Store.GetGroup(value.ID())
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		if err == nil && got.BuiltIn {
			writeError(w, http.StatusBadRequest, "ValidationError", "Built-in groups cannot be deleted.", value.ID())
			return
		}
		if err := h.Store.DeleteGroup(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) groupUser(w http.ResponseWriter, r *http.Request, group model.Group, user model.User) {
	if _, err := h.Store.GetUser(user.ID()); err != nil {
		h.storeError(w, err, user.ID())
		return
	}
	exists, err := h.Store.HasGroupUser(group.ID(), user.ID())
	if err != nil {
		h.storeError(w, err, user.ID())
		return
	}
	switch r.Method {
	case http.MethodHead:
		if !exists {
			h.storeError(w, store.ErrNotFound, user.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPut:
		if err := h.Store.LinkGroupUser(group.ID(), user.ID()); err != nil {
			h.storeError(w, err, user.ID())
			return
		}
		status := http.StatusCreated
		if exists {
			status = http.StatusOK
		}
		got, _ := h.Store.GetUser(user.ID())
		writeResource(w, status, userWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.UnlinkGroupUser(group.ID(), user.ID()); err != nil {
			h.storeError(w, err, user.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) user(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListUsers(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, userWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	value := model.User{ServiceID: scope, Name: rt.Tail[1], State: "active"}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "groups") {
		if _, err := h.Store.GetUser(value.ID()); err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListUserGroups(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, group := range values {
			resources = append(resources, groupWire(group))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "generateSsoUrl") {
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		got, err := h.Store.GetUser(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		expiry := time.Unix(h.Store.Clock.Now(), 0).Add(5 * time.Minute)
		token := userToken(got, "primary", expiry)
		writeJSON(w, http.StatusOK, map[string]any{"value": absolute(r, "/signin-sso?token="+url.QueryEscape(token))})
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "token") {
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		got, err := h.Store.GetUser(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		var body struct {
			Properties struct {
				KeyType string    `json:"keyType"`
				Expiry  time.Time `json:"expiry"`
			} `json:"properties"`
		}
		if err := decode(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		now := time.Unix(h.Store.Clock.Now(), 0)
		if body.Properties.KeyType != "primary" && body.Properties.KeyType != "secondary" {
			writeError(w, http.StatusBadRequest, "ValidationError", "keyType must be primary or secondary.", "properties.keyType")
			return
		}
		if !body.Properties.Expiry.After(now) || body.Properties.Expiry.After(now.Add(30*24*time.Hour)) {
			writeError(w, http.StatusBadRequest, "ValidationError", "expiry must be in the next 30 days.", "properties.expiry")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": userToken(got, body.Properties.KeyType, body.Properties.Expiry)})
		return
	}
	if len(rt.Tail) != 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested user resource was not found.", r.URL.Path)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetUser(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, userWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetUser(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if existingErr == nil {
			value = existing
		} else if r.Method == http.MethodPatch {
			h.storeError(w, existingErr, value.ID())
			return
		}
		var body struct {
			Properties struct {
				FirstName  *string               `json:"firstName"`
				LastName   *string               `json:"lastName"`
				Email      *string               `json:"email"`
				State      *string               `json:"state"`
				Note       *string               `json:"note"`
				Password   *string               `json:"password"`
				Identities *[]model.UserIdentity `json:"identities"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = userWire(value)
			}
			mergeObject(value.Document, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		sanitizeUserDocument(value.Document)
		if body.Properties.FirstName != nil {
			value.FirstName = *body.Properties.FirstName
		}
		if body.Properties.LastName != nil {
			value.LastName = *body.Properties.LastName
		}
		if body.Properties.Email != nil {
			value.Email = *body.Properties.Email
		}
		if body.Properties.State != nil {
			value.State = *body.Properties.State
		}
		if body.Properties.Note != nil {
			value.Note = *body.Properties.Note
		}
		if body.Properties.Password != nil {
			value.Password = *body.Properties.Password
		}
		if body.Properties.Identities != nil {
			value.Identities = *body.Properties.Identities
		}
		clearNullUserProperties(&value, document)
		if strings.TrimSpace(value.FirstName) == "" || strings.TrimSpace(value.LastName) == "" || strings.TrimSpace(value.Email) == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "firstName, lastName, and email are required.", "properties")
			return
		}
		if value.State != "active" && value.State != "blocked" && value.State != "deleted" && value.State != "pending" {
			writeError(w, http.StatusBadRequest, "ValidationError", "invalid user state.", "properties.state")
			return
		}
		got, err := h.Store.UpsertUser(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, userWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteUser(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func userToken(user model.User, keyType string, expiry time.Time) string {
	key := user.PrimaryKey
	if keyType == "secondary" {
		key = user.SecondaryKey
	}
	expires := expiry.UTC().Format(time.RFC3339)
	message := user.ID() + "\n" + expires
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(message))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return "SharedAccessSignature uid=" + url.QueryEscape(user.ID()) + "&ex=" + url.QueryEscape(expires) + "&sn=" + url.QueryEscape(user.Name) + "&skn=" + keyType + "&sig=" + url.QueryEscape(signature)
}

func (h *Handler) policyFragment(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListPolicyFragments(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, policyFragmentWire(value, r.URL.Query().Get("format")))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	value := model.PolicyFragment{ServiceID: scope, Name: rt.Tail[1], Format: "xml", ProvisioningState: "Succeeded"}
	if len(rt.Tail) == 3 && (equal(rt.Tail[2], "references") || equal(rt.Tail[2], "listReferences")) {
		method := http.MethodGet
		if equal(rt.Tail[2], "listReferences") {
			method = http.MethodPost
		}
		if r.Method != method {
			methodNotAllowed(w)
			return
		}
		if _, err := h.Store.GetPolicyFragment(value.ID()); err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		references, err := h.Store.ListPolicyFragmentReferences(scope, value.Name)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		resources := make([]map[string]any, 0, len(references))
		for _, reference := range references {
			resources = append(resources, map[string]any{"id": reference.ScopeID, "name": "policy", "type": "Microsoft.ApiManagement/service/apis/policies"})
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) != 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested policy fragment resource was not found.", r.URL.Path)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetPolicyFragment(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, policyFragmentWire(got, r.URL.Query().Get("format")), got.ETag)
	case http.MethodPut:
		_, existingErr := h.Store.GetPolicyFragment(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		var body struct {
			Properties struct {
				Description string `json:"description"`
				Format      string `json:"format"`
				Value       string `json:"value"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		value.Document = document
		cleanResourceDocument(value.Document)
		if body.Properties.Format != "" {
			value.Format = body.Properties.Format
		}
		value.Description, value.Value = body.Properties.Description, body.Properties.Value
		if value.Format != "xml" && value.Format != "rawxml" {
			writeError(w, http.StatusBadRequest, "ValidationError", "format must be xml or rawxml.", "properties.format")
			return
		}
		if err := policy.ValidateFragment(value.Value); err != nil {
			writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties.value")
			return
		}
		got, err := h.Store.UpsertPolicyFragment(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		status := http.StatusOK
		if errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, policyFragmentWire(got, ""), got.ETag)
	case http.MethodDelete:
		references, err := h.Store.ListPolicyFragmentReferences(scope, value.Name)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if len(references) != 0 {
			writeError(w, http.StatusConflict, "ResourceInUse", "The policy fragment is referenced by a policy.", value.ID())
			return
		}
		if err := h.Store.DeletePolicyFragment(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) apiSchemaCollection(w http.ResponseWriter, r *http.Request, api model.API) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	values, err := h.Store.ListAPISchemas(api.ID())
	if err != nil {
		h.storeError(w, err, api.ID())
		return
	}
	resources := make([]map[string]any, 0, len(values))
	for _, value := range values {
		resources = append(resources, apiSchemaWire(value))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
}

func (h *Handler) apiSchemaResource(w http.ResponseWriter, r *http.Request, value model.APISchema) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetAPISchema(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, apiSchemaWire(got), got.ETag)
	case http.MethodPut:
		_, existingErr := h.Store.GetAPISchema(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		var body struct {
			Properties struct {
				ContentType string         `json:"contentType"`
				Document    map[string]any `json:"document"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if _, _, err := mime.ParseMediaType(body.Properties.ContentType); err != nil || !strings.Contains(body.Properties.ContentType, "/") {
			writeError(w, http.StatusBadRequest, "ValidationError", "properties.contentType must be a valid media type.", "properties.contentType")
			return
		}
		value.ContentType, value.Document, value.ARMDocument = body.Properties.ContentType, body.Properties.Document, document
		cleanResourceDocument(value.ARMDocument)
		got, err := h.Store.UpsertAPISchema(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		// A schema is runtime state, not just metadata: a GraphQL schema decides
		// what the gateway will accept. Without republishing here, an imported
		// schema would sit in the store while the gateway kept serving the API
		// as if it had none.
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), value.ID())
			return
		}
		writeResource(w, status, apiSchemaWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteAPISchema(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		// The row is already gone, so this reports a republish failure rather
		// than a rejected request: 500 ConfigurationInvalid, matching every
		// other delete-then-activate path here.
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

type apiPayload struct {
	Properties struct {
		DisplayName            *string   `json:"displayName"`
		Path                   *string   `json:"path"`
		ServiceURL             *string   `json:"serviceUrl"`
		Protocols              *[]string `json:"protocols"`
		SubscriptionRequired   *bool     `json:"subscriptionRequired"`
		APIRevision            *string   `json:"apiRevision"`
		APIRevisionDescription *string   `json:"apiRevisionDescription"`
		IsCurrent              *bool     `json:"isCurrent"`
		SourceAPIID            *string   `json:"sourceApiId"`
		APIVersion             *string   `json:"apiVersion"`
		APIVersionSetID        *string   `json:"apiVersionSetId"`
		Format                 *string   `json:"format"`
		Value                  *string   `json:"value"`
	} `json:"properties"`
}

func (h *Handler) apiResource(w http.ResponseWriter, r *http.Request, api model.API) {
	switch r.Method {
	case http.MethodGet:
		if r.URL.Query().Get("export") == "true" {
			h.apiExport(w, r, api)
			return
		}
		got, err := h.Store.GetAPI(api.ID())
		if err != nil {
			h.storeError(w, err, api.ID())
			return
		}
		writeResource(w, http.StatusOK, apiWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetAPI(api.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, api.ID())
			return
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, api.ID())
				return
			}
			api = existing
		} else {
			api.SubscriptionRequired = true
			api.IsCurrent = !strings.Contains(strings.ToLower(api.Name), ";rev=")
		}
		var body apiPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		cloneSourceID := ""
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) && body.Properties.SourceAPIID != nil {
			targetName := api.Name
			source, sourceID, err := h.revisionSource(*body.Properties.SourceAPIID)
			if err != nil {
				h.storeError(w, err, *body.Properties.SourceAPIID)
				return
			}
			api = source
			api.Name, api.Revision, api.RevisionDescription = targetName, "", ""
			api.IsCurrent, api.CreatedAt, api.UpdatedAt, api.ETag = false, 0, 0, ""
			cloneSourceID = sourceID
		}
		if r.Method == http.MethodPatch || cloneSourceID != "" {
			if api.Document == nil {
				api.Document = apiWire(api)
			}
			mergeObject(api.Document, document)
		} else {
			api.Document = document
		}
		cleanAPIDocument(api.Document)
		applyAPIPayload(&api, body)
		clearNullAPIProperties(&api, document)
		var imported *struct {
			definition model.APIDefinition
			operations []model.Operation
			schema     *model.APISchema
		}
		if body.Properties.Format != nil {
			if r.Method != http.MethodPut || body.Properties.Value == nil {
				writeError(w, http.StatusBadRequest, "ValidationError", "format and value are required for API import.", "properties")
				return
			}
			source, sourceURL, err := h.resolveImport(r, *body.Properties.Format, *body.Properties.Value)
			if err != nil {
				writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties.value")
				return
			}
			// WSDL is a different document with a different parser. Azure
			// imports SOAP through this same format/value pair rather than
			// through a schema sub-resource, so following that shape is what
			// keeps a caller's import script portable.
			if isWSDLFormat(*body.Properties.Format) {
				wsdl, err := soapc.Parse(source)
				if err != nil {
					writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties.value")
					return
				}
				if body.Properties.DisplayName == nil && wsdl.ServiceName != "" {
					api.DisplayName = wsdl.ServiceName
				}
				markSOAPAPIType(api.Document)
				imported = &struct {
					definition model.APIDefinition
					operations []model.Operation
					schema     *model.APISchema
				}{model.APIDefinition{Format: *body.Properties.Format, Value: source, SourceURL: sourceURL}, wsdlOperations(wsdl), nil}
			} else {
				parsed, err := openapic.Parse(source)
				if err != nil {
					writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties.value")
					return
				}
				if body.Properties.DisplayName == nil {
					api.DisplayName = parsed.Title
				}
				if body.Properties.ServiceURL == nil {
					api.ServiceURL = parsed.ServiceURL
				}
				if body.Properties.Protocols == nil && api.ServiceURL != "" {
					protocol := "http"
					if parsedURL, err := url.Parse(api.ServiceURL); err == nil && parsedURL.Scheme == "https" {
						protocol = "https"
					}
					api.Protocols = []string{protocol}
				}
				var schema *model.APISchema
				if len(parsed.Schemas) != 0 {
					contentType, key := "application/vnd.oai.openapi.components+json", "components"
					if parsed.Version == "2.0" {
						contentType, key = "application/vnd.ms-azure-apim.swagger.definitions+json", "definitions"
					}
					schema = &model.APISchema{ContentType: contentType, Document: map[string]any{key: parsed.Schemas}}
				}
				imported = &struct {
					definition model.APIDefinition
					operations []model.Operation
					schema     *model.APISchema
				}{model.APIDefinition{Format: *body.Properties.Format, Value: source, SourceURL: sourceURL}, parsed.Operations, schema}
			}
		}
		// A SYNTHETIC GraphQL API has no backend by definition: its fields come
		// from resolvers, and requiring a serviceUrl would make the shape
		// impossible to create. Pass-through GraphQL still needs one, but that
		// is not knowable here, and the gateway reports a missing backend at
		// request time rather than guessing at import time.
		if api.DisplayName == "" || (api.ServiceURL == "" && !isGraphQLAPIDocument(document)) {
			writeError(w, http.StatusBadRequest, "ValidationError", "displayName and serviceUrl are required.", "properties")
			return
		}
		if (api.Version == "") != (api.VersionSetID == "") {
			writeError(w, http.StatusBadRequest, "ValidationError", "apiVersion and apiVersionSetId must be supplied together.", "properties")
			return
		}
		var got model.API
		var err error
		if imported != nil {
			got, err = h.Store.ImportAPI(api, imported.definition, imported.operations, imported.schema)
		} else if cloneSourceID != "" {
			got, err = h.Store.CloneAPIRevision(cloneSourceID, api)
		} else {
			got, err = h.Store.UpsertAPI(api)
		}
		if err != nil {
			h.storeError(w, err, api.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), api.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, apiWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteAPI(api.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, api.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), api.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

const maxImportBytes = 4 << 20

// guardImportHost mitigates SSRF on the linked-import feature: it blocks
// fetching an API definition from a link-local / cloud-metadata address (the
// classic target, e.g. 169.254.169.254), while still allowing loopback and
// private hosts, which are normal when importing from a nearby backend during
// local development. It resolves the host and rejects if any resolved address
// is link-local, multicast, or unspecified. (Import-from-link is a first-class
// Azure APIM feature that inherently fetches an operator-supplied URL; this
// removes the dangerous targets without disabling the feature.)
// lookupIP resolves a hostname to IPs; a package var so tests can drive the
// resolution-failure branch deterministically without depending on real DNS.
var lookupIP = net.LookupIP

func guardImportHost(host string) error {
	if host == "" {
		return errors.New("linked API definition URL has no host")
	}
	var ips []net.IP
	if literal := net.ParseIP(host); literal != nil {
		ips = []net.IP{literal}
	} else {
		resolved, err := lookupIP(host)
		if err != nil {
			return fmt.Errorf("linked API definition host %q could not be resolved", host)
		}
		ips = resolved
	}
	for _, ip := range ips {
		if importAddressBlocked(ip) {
			return errors.New("linked API definition host is not allowed (link-local or metadata address)")
		}
	}
	return nil
}

// importAddressBlocked reports whether an IP is a forbidden SSRF target for the
// linked-import fetch: link-local (169.254.0.0/16, fe80::/10 — covers the
// 169.254.169.254 cloud-metadata endpoint), multicast, or the unspecified
// address. Loopback and private ranges stay allowed, since importing from a
// nearby backend is normal in local development.
func importAddressBlocked(ip net.IP) bool {
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

// newImportClient builds the HTTP client used to fetch linked API definitions.
// guardImportHost checks the host before the request, but that is a
// time-of-check/time-of-use gap: DNS can rebind between the check and the
// dial, resolving to a blocked address on the actual connection. The Control
// hook runs after resolution, immediately before connect, on the real
// destination IP — so it closes that gap regardless of what DNS returns.
func newImportClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: importDialControl}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DialContext: dialer.DialContext},
	}
}

// importDialControl is the net.Dialer.Control hook for the import client: it
// runs on the resolved destination immediately before connect and refuses a
// blocked SSRF target, closing the DNS-rebind gap. Split out (rather than an
// inline closure) so every branch is directly testable — a real dial always
// supplies host:port, so the malformed-address path is otherwise unreachable.
func importDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || importAddressBlocked(ip) {
		return errors.New("linked API definition host is not allowed (link-local or metadata address)")
	}
	return nil
}

func (h *Handler) resolveImport(r *http.Request, format, value string) (string, string, error) {
	linked := format == "openapi-link" || format == "openapi+json-link" || format == "swagger-link-json" ||
		strings.EqualFold(format, "wsdl-link")
	if !linked {
		if format != "openapi" && format != "openapi+json" && format != "swagger-json" && !strings.EqualFold(format, "wsdl") {
			return "", "", fmt.Errorf("unsupported import format %q", format)
		}
		if len(value) > maxImportBytes {
			return "", "", errors.New("API definition exceeds the 4 MiB import limit")
		}
		return value, "", nil
	}
	sourceURL, err := url.Parse(value)
	if err != nil || (sourceURL.Scheme != "http" && sourceURL.Scheme != "https") || sourceURL.Host == "" {
		return "", "", errors.New("linked API definition must be an absolute HTTP or HTTPS URL")
	}
	if err := guardImportHost(sourceURL.Hostname()); err != nil {
		return "", "", err
	}
	client := h.ImportClient
	if client == nil {
		client = newImportClient()
	}
	request, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, sourceURL.String(), nil)
	response, err := client.Do(request)
	if err != nil {
		return "", "", fmt.Errorf("retrieve linked API definition: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("linked API definition returned HTTP %d", response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maxImportBytes+1))
	if err != nil {
		return "", "", fmt.Errorf("read linked API definition: %w", err)
	}
	if len(content) > maxImportBytes {
		return "", "", errors.New("API definition exceeds the 4 MiB import limit")
	}
	return string(content), sourceURL.String(), nil
}

func (h *Handler) apiExport(w http.ResponseWriter, r *http.Request, api model.API) {
	got, err := h.Store.GetAPI(api.ID())
	if err != nil {
		h.storeError(w, err, api.ID())
		return
	}
	format := r.URL.Query().Get("format")
	_, resultFormat, _, err := h.renderAPIExport(got, format)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "format")
		return
	}
	expires := h.Store.Clock.Now() + 300
	signature := h.exportSignature(got.ID(), format, expires)
	query := url.Values{"api-version": {r.URL.Query().Get("api-version")}, "export": {"download"}, "format": {format}, "expires": {fmt.Sprint(expires)}, "sig": {signature}}
	link := absolute(r, r.URL.Path+"?"+query.Encode())
	writeJSON(w, http.StatusOK, map[string]any{"id": got.ID(), "format": resultFormat, "value": map[string]any{"link": link}})
}

func (h *Handler) apiExportDownload(w http.ResponseWriter, r *http.Request) {
	version := r.URL.Query().Get("api-version")
	parsed, ok := parse(split(r.URL.Path))
	if !supportedVersions[version] || !ok || len(parsed.Tail) != 2 || !equal(parsed.Tail[0], "apis") {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The API export was not found.", r.URL.Path)
		return
	}
	expires, err := strconv.ParseInt(r.URL.Query().Get("expires"), 10, 64)
	api := model.API{ServiceID: model.Service{SubscriptionID: parsed.SubscriptionID, ResourceGroup: parsed.ResourceGroup, Name: parsed.ServiceName}.ID(), Name: parsed.Tail[1]}
	format := r.URL.Query().Get("format")
	if err != nil || !hmac.Equal([]byte(r.URL.Query().Get("sig")), []byte(h.exportSignature(api.ID(), format, expires))) {
		writeError(w, http.StatusForbidden, "AuthorizationFailed", "The API export link is invalid.", "sig")
		return
	}
	if h.Store.Clock.Now() > expires {
		writeError(w, http.StatusGone, "ExportExpired", "The API export link has expired.", "expires")
		return
	}
	got, err := h.Store.GetAPI(api.ID())
	if err != nil {
		h.storeError(w, err, api.ID())
		return
	}
	content, _, contentType, err := h.renderAPIExport(got, format)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "format")
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (h *Handler) renderAPIExport(api model.API, format string) ([]byte, string, string, error) {
	operations, err := h.Store.ListOperations(api.ID())
	if err != nil {
		return nil, "", "", err
	}
	schemas, err := h.Store.ListAPISchemas(api.ID())
	if err != nil {
		return nil, "", "", err
	}
	definitions := map[string]any{}
	for _, schema := range schemas {
		if schema.Name != "openapi" {
			continue
		}
		if values, ok := schema.Document["components"].(map[string]any); ok {
			definitions = values
		}
		if values, ok := schema.Document["definitions"].(map[string]any); ok {
			definitions = values
		}
	}
	return openapic.Export(api, operations, definitions, format)
}

func (h *Handler) exportSignature(apiID, format string, expires int64) string {
	key := h.ExportKey
	if len(key) == 0 {
		key = []byte("azure-apim-emulator-local-export")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = fmt.Fprintf(mac, "%s\n%s\n%d", strings.ToLower(apiID), format, expires)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (h *Handler) revisionSource(id string) (model.API, string, error) {
	value, err := h.Store.GetAPI(id)
	if errors.Is(err, store.ErrNotFound) && strings.HasSuffix(strings.ToLower(id), ";rev=1") {
		id = id[:len(id)-6]
		value, err = h.Store.GetAPI(id)
	}
	return value, id, err
}

func applyAPIPayload(api *model.API, body apiPayload) {
	if body.Properties.DisplayName != nil {
		api.DisplayName = *body.Properties.DisplayName
	}
	if body.Properties.Path != nil {
		api.Path = *body.Properties.Path
	}
	if body.Properties.ServiceURL != nil {
		api.ServiceURL = *body.Properties.ServiceURL
	}
	if body.Properties.Protocols != nil {
		api.Protocols = *body.Properties.Protocols
	}
	if body.Properties.SubscriptionRequired != nil {
		api.SubscriptionRequired = *body.Properties.SubscriptionRequired
	}
	if body.Properties.APIRevision != nil {
		api.Revision = *body.Properties.APIRevision
	}
	if body.Properties.APIRevisionDescription != nil {
		api.RevisionDescription = *body.Properties.APIRevisionDescription
	}
	if body.Properties.IsCurrent != nil {
		api.IsCurrent = *body.Properties.IsCurrent
	}
	if body.Properties.APIVersion != nil {
		api.Version = *body.Properties.APIVersion
	}
	if body.Properties.APIVersionSetID != nil {
		api.VersionSetID = *body.Properties.APIVersionSetID
	}
}

func cleanAPIDocument(document map[string]any) {
	cleanResourceDocument(document)
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "format")
	delete(properties, "value")
	delete(properties, "sourceApiId")
}

func clearNullAPIProperties(api *model.API, patch map[string]any) {
	properties, _ := patch["properties"].(map[string]any)
	if value, present := properties["apiRevisionDescription"]; present && value == nil {
		api.RevisionDescription = ""
	}
	if value, present := properties["apiVersion"]; present && value == nil {
		api.Version = ""
	}
	if value, present := properties["apiVersionSetId"]; present && value == nil {
		api.VersionSetID = ""
	}
}

func (h *Handler) apiVersionSet(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListAPIVersionSets(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, apiVersionSetWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) != 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested API version set resource was not found.", r.URL.Path)
		return
	}
	value := model.APIVersionSet{ServiceID: scope, Name: rt.Tail[1]}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetAPIVersionSet(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, apiVersionSetWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetAPIVersionSet(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, value.ID())
				return
			}
			value = existing
		}
		var body struct {
			Properties struct {
				DisplayName       *string `json:"displayName"`
				VersioningScheme  *string `json:"versioningScheme"`
				VersionHeaderName *string `json:"versionHeaderName"`
				VersionQueryName  *string `json:"versionQueryName"`
				Description       *string `json:"description"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = apiVersionSetWire(value)
			}
			mergeObject(value.Document, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		if body.Properties.DisplayName != nil {
			value.DisplayName = *body.Properties.DisplayName
		}
		if body.Properties.VersioningScheme != nil {
			value.VersioningScheme = *body.Properties.VersioningScheme
		}
		if body.Properties.VersionHeaderName != nil {
			value.VersionHeaderName = *body.Properties.VersionHeaderName
		}
		if body.Properties.VersionQueryName != nil {
			value.VersionQueryName = *body.Properties.VersionQueryName
		}
		if body.Properties.Description != nil {
			value.Description = *body.Properties.Description
		}
		properties, _ := document["properties"].(map[string]any)
		if field, present := properties["versionHeaderName"]; present && field == nil {
			value.VersionHeaderName = ""
		}
		if field, present := properties["versionQueryName"]; present && field == nil {
			value.VersionQueryName = ""
		}
		if field, present := properties["description"]; present && field == nil {
			value.Description = ""
		}
		if err := validateAPIVersionSet(value); err != nil {
			writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties")
			return
		}
		got, err := h.Store.UpsertAPIVersionSet(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, apiVersionSetWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteAPIVersionSet(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func validateAPIVersionSet(value model.APIVersionSet) error {
	if value.DisplayName == "" || (value.VersioningScheme != "Segment" && value.VersioningScheme != "Header" && value.VersioningScheme != "Query") {
		return errors.New("displayName and a valid versioningScheme are required")
	}
	if value.VersioningScheme == "Header" && value.VersionHeaderName == "" {
		return errors.New("versionHeaderName is required for Header versioning")
	}
	if value.VersioningScheme == "Query" && value.VersionQueryName == "" {
		return errors.New("versionQueryName is required for Query versioning")
	}
	return nil
}

type namedValuePayload struct {
	Properties struct {
		DisplayName *string   `json:"displayName"`
		Value       *string   `json:"value"`
		Tags        *[]string `json:"tags"`
		Secret      *bool     `json:"secret"`
		KeyVault    *struct {
			SecretIdentifier *string `json:"secretIdentifier"`
			IdentityClientID *string `json:"identityClientId"`
		} `json:"keyVault"`
	} `json:"properties"`
}

func (h *Handler) namedValue(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListNamedValues(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, namedValueWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) < 2 || len(rt.Tail) > 3 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested named value resource was not found.", r.URL.Path)
		return
	}
	value := model.NamedValue{ServiceID: scope, Name: rt.Tail[1]}
	if len(rt.Tail) == 3 {
		h.namedValueAction(w, r, value, rt.Tail[2])
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetNamedValue(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, namedValueWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetNamedValue(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, value.ID())
				return
			}
			value = existing
		}
		var body namedValuePayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = namedValueWire(value)
			}
			mergeObject(value.Document, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		sanitizeNamedValueDocument(value.Document)
		applyNamedValuePayload(&value, body)
		clearNullNamedValueProperties(&value, document)
		if value.DisplayName == "" || len(value.DisplayName) > 256 || !namedValueDisplayName.MatchString(value.DisplayName) ||
			(strings.TrimSpace(value.Value) == "" && value.KeyVaultSecretID == "") || len(value.Value) > 4096 {
			writeError(w, http.StatusBadRequest, "ValidationError", "displayName must be a valid named-value identifier and either value or keyVault.secretIdentifier is required.", "properties")
			return
		}
		if value.KeyVaultSecretID != "" {
			h.refreshNamedValueSecret(r.Context(), &value)
		}
		got, err := h.Store.UpsertNamedValue(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, namedValueWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteNamedValue(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) namedValueAction(w http.ResponseWriter, r *http.Request, value model.NamedValue, action string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	got, err := h.Store.GetNamedValue(value.ID())
	if err != nil {
		h.storeError(w, err, value.ID())
		return
	}
	switch action {
	case "listValue":
		writeResource(w, http.StatusOK, map[string]any{"value": got.Value}, got.ETag)
	case "refreshSecret":
		if got.KeyVaultSecretID == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "refreshSecret requires a Key Vault-backed named value.", value.ID())
			return
		}
		h.refreshNamedValueSecret(r.Context(), &got)
		updated, err := h.Store.UpsertNamedValue(got)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		writeResource(w, http.StatusOK, namedValueWire(updated), updated.ETag)
	default:
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested named value action was not found.", r.URL.Path)
	}
}

func applyNamedValuePayload(value *model.NamedValue, body namedValuePayload) {
	if body.Properties.DisplayName != nil {
		value.DisplayName = *body.Properties.DisplayName
	}
	if body.Properties.Value != nil {
		value.Value = *body.Properties.Value
	}
	if body.Properties.Tags != nil {
		value.Tags = *body.Properties.Tags
	}
	if body.Properties.Secret != nil {
		value.Secret = *body.Properties.Secret
	}
	if body.Properties.KeyVault != nil {
		if body.Properties.KeyVault.SecretIdentifier != nil {
			value.KeyVaultSecretID = *body.Properties.KeyVault.SecretIdentifier
		}
		if body.Properties.KeyVault.IdentityClientID != nil {
			value.KeyVaultIdentityID = *body.Properties.KeyVault.IdentityClientID
		}
	}
}

func sanitizeNamedValueDocument(document map[string]any) {
	delete(document, "value")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "value")
}

func clearNullNamedValueProperties(value *model.NamedValue, patch map[string]any) {
	properties, _ := patch["properties"].(map[string]any)
	if field, present := properties["displayName"]; present && field == nil {
		value.DisplayName = ""
	}
	if field, present := properties["value"]; present && field == nil {
		value.Value = ""
	}
	if field, present := properties["tags"]; present && field == nil {
		value.Tags = nil
	}
	if field, present := properties["secret"]; present && field == nil {
		value.Secret = false
	}
	if field, present := properties["keyVault"]; present && field == nil {
		value.KeyVaultSecretID, value.KeyVaultIdentityID = "", ""
		return
	}
	keyVault, _ := properties["keyVault"].(map[string]any)
	if field, present := keyVault["secretIdentifier"]; present && field == nil {
		value.KeyVaultSecretID = ""
	}
	if field, present := keyVault["identityClientId"]; present && field == nil {
		value.KeyVaultIdentityID = ""
	}
}

type backendPayload struct {
	Properties struct {
		Title       *string `json:"title"`
		Description *string `json:"description"`
		URL         *string `json:"url"`
		Protocol    *string `json:"protocol"`
		ResourceID  *string `json:"resourceId"`
	} `json:"properties"`
}

func (h *Handler) backend(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListBackends(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, backendWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) < 2 || len(rt.Tail) > 3 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested backend resource was not found.", r.URL.Path)
		return
	}
	value := model.Backend{ServiceID: scope, Name: rt.Tail[1]}
	if len(rt.Tail) == 3 {
		if rt.Tail[2] != "reconnect" {
			writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested backend action was not found.", r.URL.Path)
			return
		}
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		got, err := h.Store.GetBackend(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		w.Header().Set("ETag", got.ETag)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetBackend(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, backendWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetBackend(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, value.ID())
				return
			}
			value = existing
		}
		var body backendPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = backendWire(value)
			}
			mergeObject(value.Document, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		applyBackendPayload(&value, body)
		clearNullBackendProperties(&value, document)
		parsedURL, urlErr := url.ParseRequestURI(value.URL)
		if value.URL == "" || urlErr != nil || parsedURL.Scheme == "" || parsedURL.Host == "" || (value.Protocol != "http" && value.Protocol != "soap") {
			writeError(w, http.StatusBadRequest, "ValidationError", "properties.url and a valid properties.protocol are required.", "properties")
			return
		}
		got, err := h.Store.UpsertBackend(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, backendWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteBackend(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func applyBackendPayload(value *model.Backend, body backendPayload) {
	if body.Properties.Title != nil {
		value.Title = *body.Properties.Title
	}
	if body.Properties.Description != nil {
		value.Description = *body.Properties.Description
	}
	if body.Properties.URL != nil {
		value.URL = *body.Properties.URL
	}
	if body.Properties.Protocol != nil {
		value.Protocol = *body.Properties.Protocol
	}
	if body.Properties.ResourceID != nil {
		value.ResourceID = *body.Properties.ResourceID
	}
}

func clearNullBackendProperties(value *model.Backend, patch map[string]any) {
	properties, _ := patch["properties"].(map[string]any)
	if field, present := properties["title"]; present && field == nil {
		value.Title = ""
	}
	if field, present := properties["description"]; present && field == nil {
		value.Description = ""
	}
	if field, present := properties["url"]; present && field == nil {
		value.URL = ""
	}
	if field, present := properties["protocol"]; present && field == nil {
		value.Protocol = ""
	}
	if field, present := properties["resourceId"]; present && field == nil {
		value.ResourceID = ""
	}
}

type cachePayload struct {
	Properties struct {
		ConnectionString *string `json:"connectionString"`
		UseFromLocation  *string `json:"useFromLocation"`
		Description      *string `json:"description"`
		ResourceID       *string `json:"resourceId"`
	} `json:"properties"`
}

func (h *Handler) cache(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListCaches(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, cacheWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) != 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested cache resource was not found.", r.URL.Path)
		return
	}
	value := model.Cache{ServiceID: scope, Name: rt.Tail[1]}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetCache(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, cacheWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetCache(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, value.ID())
				return
			}
			value = existing
		}
		var body cachePayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = cacheWire(value)
			}
			mergeObject(value.Document, document)
			clearNullCacheProperties(&value, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		sanitizeCacheDocument(value.Document)
		applyCachePayload(&value, body)
		if err := validateCache(value, r.Method == http.MethodPut); err != nil {
			writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties")
			return
		}
		got, err := h.Store.UpsertCache(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, cacheWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteCache(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func applyCachePayload(value *model.Cache, body cachePayload) {
	if body.Properties.ConnectionString != nil {
		value.ConnectionString = *body.Properties.ConnectionString
	}
	if body.Properties.UseFromLocation != nil {
		value.UseFromLocation = *body.Properties.UseFromLocation
	}
	if body.Properties.Description != nil {
		value.Description = *body.Properties.Description
	}
	if body.Properties.ResourceID != nil {
		value.ResourceID = *body.Properties.ResourceID
	}
	if strings.EqualFold(value.UseFromLocation, "default") {
		value.UseFromLocation = "default"
	}
}

func clearNullCacheProperties(value *model.Cache, document map[string]any) {
	properties, _ := document["properties"].(map[string]any)
	if field, present := properties["description"]; present && field == nil {
		value.Description = ""
	}
	if field, present := properties["resourceId"]; present && field == nil {
		value.ResourceID = ""
	}
}

func validateCache(value model.Cache, creating bool) error {
	if creating && value.ConnectionString == "" {
		return errors.New("connectionString is required")
	}
	if creating && value.UseFromLocation == "" {
		return errors.New("useFromLocation is required")
	}
	if value.ConnectionString == "" {
		return errors.New("connectionString cannot be empty")
	}
	if value.UseFromLocation == "" {
		return errors.New("useFromLocation cannot be empty")
	}
	if len(value.ConnectionString) > 300 {
		return errors.New("connectionString must be at most 300 characters")
	}
	if len(value.UseFromLocation) > 256 {
		return errors.New("useFromLocation must be at most 256 characters")
	}
	if len(value.Description) > 2000 {
		return errors.New("description must be at most 2000 characters")
	}
	if len(value.ResourceID) > 2000 {
		return errors.New("resourceId must be at most 2000 characters")
	}
	return nil
}

func sanitizeCacheDocument(document map[string]any) {
	if document == nil {
		return
	}
	delete(document, "connectionString")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "connectionString")
}

type identityProviderPayload struct {
	Properties struct {
		Type                     *string   `json:"type"`
		ClientID                 *string   `json:"clientId"`
		ClientSecret             *string   `json:"clientSecret"`
		Authority                *string   `json:"authority"`
		SigninTenant             *string   `json:"signinTenant"`
		SignupPolicyName         *string   `json:"signupPolicyName"`
		SigninPolicyName         *string   `json:"signinPolicyName"`
		ProfileEditingPolicyName *string   `json:"profileEditingPolicyName"`
		PasswordResetPolicyName  *string   `json:"passwordResetPolicyName"`
		AllowedTenants           *[]string `json:"allowedTenants"`
		ClientLibrary            *string   `json:"clientLibrary"`
	} `json:"properties"`
}

var identityProviderNames = map[string]string{
	"facebook":  "facebook",
	"google":    "google",
	"microsoft": "microsoft",
	"twitter":   "twitter",
	"aad":       "aad",
	"aadb2c":    "aadB2C",
}

func canonicalizeIdentityProviderName(name string) (string, bool) {
	canonical, ok := identityProviderNames[strings.ToLower(name)]
	return canonical, ok
}

func (h *Handler) identityProvider(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListIdentityProviders(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, identityProviderWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) < 2 || len(rt.Tail) > 3 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested identity provider resource was not found.", r.URL.Path)
		return
	}
	name, ok := canonicalizeIdentityProviderName(rt.Tail[1])
	if !ok {
		writeError(w, http.StatusBadRequest, "ValidationError", "identityProviderName must be facebook, google, microsoft, twitter, aad, or aadB2C.", "identityProviderName")
		return
	}
	value := model.IdentityProvider{ServiceID: scope, Name: name}
	if len(rt.Tail) == 3 {
		h.identityProviderAction(w, r, value, rt.Tail[2])
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetIdentityProvider(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, identityProviderWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetIdentityProvider(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, value.ID())
				return
			}
			value = existing
		}
		var body identityProviderPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if body.Properties.Type != nil {
			canonical, typeOK := canonicalizeIdentityProviderName(*body.Properties.Type)
			if !typeOK || canonical != value.Name {
				writeError(w, http.StatusBadRequest, "ValidationError", "type must match the identity provider name.", "properties.type")
				return
			}
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = identityProviderWire(value)
			}
			mergeObject(value.Document, document)
			clearNullIdentityProviderProperties(&value, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		sanitizeIdentityProviderDocument(value.Document)
		applyIdentityProviderPayload(&value, body)
		if err := validateIdentityProvider(value, r.Method == http.MethodPut); err != nil {
			writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties")
			return
		}
		got, err := h.Store.UpsertIdentityProvider(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, identityProviderWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteIdentityProvider(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) identityProviderAction(w http.ResponseWriter, r *http.Request, value model.IdentityProvider, action string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !equal(action, "listSecrets") {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested identity provider action was not found.", r.URL.Path)
		return
	}
	got, err := h.Store.GetIdentityProvider(value.ID())
	if err != nil {
		h.storeError(w, err, value.ID())
		return
	}
	writeResource(w, http.StatusOK, map[string]any{"clientSecret": got.ClientSecret}, got.ETag)
}

func applyIdentityProviderPayload(value *model.IdentityProvider, body identityProviderPayload) {
	if body.Properties.ClientID != nil {
		value.ClientID = *body.Properties.ClientID
	}
	if body.Properties.ClientSecret != nil {
		value.ClientSecret = *body.Properties.ClientSecret
	}
	if body.Properties.Authority != nil {
		value.Authority = *body.Properties.Authority
	}
	if body.Properties.SigninTenant != nil {
		value.SigninTenant = *body.Properties.SigninTenant
	}
	if body.Properties.SignupPolicyName != nil {
		value.SignupPolicyName = *body.Properties.SignupPolicyName
	}
	if body.Properties.SigninPolicyName != nil {
		value.SigninPolicyName = *body.Properties.SigninPolicyName
	}
	if body.Properties.ProfileEditingPolicyName != nil {
		value.ProfileEditingPolicyName = *body.Properties.ProfileEditingPolicyName
	}
	if body.Properties.PasswordResetPolicyName != nil {
		value.PasswordResetPolicyName = *body.Properties.PasswordResetPolicyName
	}
	if body.Properties.AllowedTenants != nil {
		value.AllowedTenants = append([]string(nil), *body.Properties.AllowedTenants...)
	}
}

func clearNullIdentityProviderProperties(value *model.IdentityProvider, document map[string]any) {
	properties, _ := document["properties"].(map[string]any)
	if field, present := properties["authority"]; present && field == nil {
		value.Authority = ""
	}
	if field, present := properties["signinTenant"]; present && field == nil {
		value.SigninTenant = ""
	}
	if field, present := properties["signupPolicyName"]; present && field == nil {
		value.SignupPolicyName = ""
	}
	if field, present := properties["signinPolicyName"]; present && field == nil {
		value.SigninPolicyName = ""
	}
	if field, present := properties["profileEditingPolicyName"]; present && field == nil {
		value.ProfileEditingPolicyName = ""
	}
	if field, present := properties["passwordResetPolicyName"]; present && field == nil {
		value.PasswordResetPolicyName = ""
	}
	if field, present := properties["allowedTenants"]; present && field == nil {
		value.AllowedTenants = []string{}
	}
}

func validateIdentityProvider(value model.IdentityProvider, creating bool) error {
	if creating && value.ClientID == "" {
		return errors.New("clientId is required")
	}
	if creating && value.ClientSecret == "" {
		return errors.New("clientSecret is required")
	}
	if value.ClientID == "" {
		return errors.New("clientId cannot be empty")
	}
	if value.ClientSecret == "" {
		return errors.New("clientSecret cannot be empty")
	}
	if library := identityProviderClientLibrary(value.Document); len(library) > 16 {
		return errors.New("clientLibrary must be at most 16 characters")
	}
	return nil
}

func identityProviderClientLibrary(document map[string]any) string {
	properties, _ := document["properties"].(map[string]any)
	value, _ := properties["clientLibrary"].(string)
	return value
}

func sanitizeIdentityProviderDocument(document map[string]any) {
	if document == nil {
		return
	}
	delete(document, "clientSecret")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "clientSecret")
}

type openIDConnectProviderPayload struct {
	Properties struct {
		DisplayName      *string `json:"displayName"`
		Description      *string `json:"description"`
		MetadataEndpoint *string `json:"metadataEndpoint"`
		ClientID         *string `json:"clientId"`
		ClientSecret     *string `json:"clientSecret"`
	} `json:"properties"`
}

func (h *Handler) openIDConnectProvider(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListOpenIDConnectProviders(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, openIDConnectProviderWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) < 2 || len(rt.Tail) > 3 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested OpenID Connect provider resource was not found.", r.URL.Path)
		return
	}
	value := model.OpenIDConnectProvider{ServiceID: scope, Name: rt.Tail[1]}
	if len(rt.Tail) == 3 {
		h.openIDConnectProviderAction(w, r, value, rt.Tail[2])
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetOpenIDConnectProvider(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, openIDConnectProviderWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetOpenIDConnectProvider(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if existingErr == nil {
			value.Name = existing.Name
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, value.ID())
				return
			}
			value = existing
		}
		var body openIDConnectProviderPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = openIDConnectProviderWire(value)
			}
			mergeObject(value.Document, document)
			clearNullOpenIDConnectProviderProperties(&value, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		sanitizeOpenIDConnectProviderDocument(value.Document)
		applyOpenIDConnectProviderPayload(&value, body)
		if err := validateOpenIDConnectProvider(value, r.Method == http.MethodPut); err != nil {
			writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties")
			return
		}
		got, err := h.Store.UpsertOpenIDConnectProvider(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, openIDConnectProviderWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteOpenIDConnectProvider(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) openIDConnectProviderAction(w http.ResponseWriter, r *http.Request, value model.OpenIDConnectProvider, action string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !equal(action, "listSecrets") {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested OpenID Connect provider action was not found.", r.URL.Path)
		return
	}
	got, err := h.Store.GetOpenIDConnectProvider(value.ID())
	if err != nil {
		h.storeError(w, err, value.ID())
		return
	}
	writeResource(w, http.StatusOK, map[string]any{"clientSecret": got.ClientSecret}, got.ETag)
}

func applyOpenIDConnectProviderPayload(value *model.OpenIDConnectProvider, body openIDConnectProviderPayload) {
	if body.Properties.DisplayName != nil {
		value.DisplayName = *body.Properties.DisplayName
	}
	if body.Properties.Description != nil {
		value.Description = *body.Properties.Description
	}
	if body.Properties.MetadataEndpoint != nil {
		value.MetadataEndpoint = *body.Properties.MetadataEndpoint
	}
	if body.Properties.ClientID != nil {
		value.ClientID = *body.Properties.ClientID
	}
	if body.Properties.ClientSecret != nil {
		value.ClientSecret = *body.Properties.ClientSecret
	}
}

func clearNullOpenIDConnectProviderProperties(value *model.OpenIDConnectProvider, document map[string]any) {
	properties, _ := document["properties"].(map[string]any)
	if field, present := properties["description"]; present && field == nil {
		value.Description = ""
	}
}

func validateOpenIDConnectProvider(value model.OpenIDConnectProvider, creating bool) error {
	if creating && value.DisplayName == "" {
		return errors.New("displayName is required")
	}
	if creating && value.MetadataEndpoint == "" {
		return errors.New("metadataEndpoint is required")
	}
	if creating && value.ClientID == "" {
		return errors.New("clientId is required")
	}
	if value.DisplayName == "" {
		return errors.New("displayName cannot be empty")
	}
	if len(value.DisplayName) > 50 {
		return errors.New("displayName must be at most 50 characters")
	}
	if value.MetadataEndpoint == "" {
		return errors.New("metadataEndpoint cannot be empty")
	}
	if value.ClientID == "" {
		return errors.New("clientId cannot be empty")
	}
	return nil
}

func sanitizeOpenIDConnectProviderDocument(document map[string]any) {
	if document == nil {
		return
	}
	delete(document, "clientSecret")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "clientSecret")
}

type authorizationServerPayload struct {
	Properties struct {
		DisplayName                *string  `json:"displayName"`
		Description                *string  `json:"description"`
		AuthorizationEndpoint      *string  `json:"authorizationEndpoint"`
		ClientRegistrationEndpoint *string  `json:"clientRegistrationEndpoint"`
		ClientID                   *string  `json:"clientId"`
		ClientSecret               *string  `json:"clientSecret"`
		TokenEndpoint              *string  `json:"tokenEndpoint"`
		DefaultScope               *string  `json:"defaultScope"`
		ResourceOwnerUsername      *string  `json:"resourceOwnerUsername"`
		ResourceOwnerPassword      *string  `json:"resourceOwnerPassword"`
		SupportState               *bool    `json:"supportState"`
		GrantTypes                 []string `json:"grantTypes"`
	} `json:"properties"`
}

var authorizationServerGrantTypes = map[string]bool{
	"authorizationCode":     true,
	"implicit":              true,
	"resourceOwnerPassword": true,
	"clientCredentials":     true,
}

func (h *Handler) authorizationServer(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListAuthorizationServers(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, authorizationServerWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) < 2 || len(rt.Tail) > 3 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested authorization server resource was not found.", r.URL.Path)
		return
	}
	value := model.AuthorizationServer{ServiceID: scope, Name: rt.Tail[1]}
	if len(rt.Tail) == 3 {
		h.authorizationServerAction(w, r, value, rt.Tail[2])
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetAuthorizationServer(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, authorizationServerWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetAuthorizationServer(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if existingErr == nil {
			value.Name = existing.Name
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, value.ID())
				return
			}
			value = existing
		}
		var body authorizationServerPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = authorizationServerWire(value)
			}
			mergeObject(value.Document, document)
			clearNullAuthorizationServerProperties(&value, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		sanitizeAuthorizationServerDocument(value.Document)
		applyAuthorizationServerPayload(&value, body)
		if err := validateAuthorizationServer(value, r.Method == http.MethodPut); err != nil {
			writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties")
			return
		}
		got, err := h.Store.UpsertAuthorizationServer(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, authorizationServerWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteAuthorizationServer(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) authorizationServerAction(w http.ResponseWriter, r *http.Request, value model.AuthorizationServer, action string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !equal(action, "listSecrets") {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested authorization server action was not found.", r.URL.Path)
		return
	}
	got, err := h.Store.GetAuthorizationServer(value.ID())
	if err != nil {
		h.storeError(w, err, value.ID())
		return
	}
	writeResource(w, http.StatusOK, map[string]any{
		"clientSecret":          got.ClientSecret,
		"resourceOwnerUsername": got.ResourceOwnerUsername,
		"resourceOwnerPassword": got.ResourceOwnerPassword,
	}, got.ETag)
}

func applyAuthorizationServerPayload(value *model.AuthorizationServer, body authorizationServerPayload) {
	if body.Properties.DisplayName != nil {
		value.DisplayName = *body.Properties.DisplayName
	}
	if body.Properties.Description != nil {
		value.Description = *body.Properties.Description
	}
	if body.Properties.AuthorizationEndpoint != nil {
		value.AuthorizationEndpoint = *body.Properties.AuthorizationEndpoint
	}
	if body.Properties.ClientRegistrationEndpoint != nil {
		value.ClientRegistrationEndpoint = *body.Properties.ClientRegistrationEndpoint
	}
	if body.Properties.ClientID != nil {
		value.ClientID = *body.Properties.ClientID
	}
	if body.Properties.ClientSecret != nil {
		value.ClientSecret = *body.Properties.ClientSecret
	}
	if body.Properties.TokenEndpoint != nil {
		value.TokenEndpoint = *body.Properties.TokenEndpoint
	}
	if body.Properties.DefaultScope != nil {
		value.DefaultScope = *body.Properties.DefaultScope
	}
	if body.Properties.ResourceOwnerUsername != nil {
		value.ResourceOwnerUsername = *body.Properties.ResourceOwnerUsername
	}
	if body.Properties.ResourceOwnerPassword != nil {
		value.ResourceOwnerPassword = *body.Properties.ResourceOwnerPassword
	}
	if body.Properties.SupportState != nil {
		value.SupportState = *body.Properties.SupportState
	}
	if body.Properties.GrantTypes != nil {
		value.GrantTypes = append([]string(nil), body.Properties.GrantTypes...)
	}
}

func clearNullAuthorizationServerProperties(value *model.AuthorizationServer, document map[string]any) {
	properties, _ := document["properties"].(map[string]any)
	if field, present := properties["description"]; present && field == nil {
		value.Description = ""
	}
	if field, present := properties["tokenEndpoint"]; present && field == nil {
		value.TokenEndpoint = ""
	}
	if field, present := properties["defaultScope"]; present && field == nil {
		value.DefaultScope = ""
	}
	if field, present := properties["resourceOwnerUsername"]; present && field == nil {
		value.ResourceOwnerUsername = ""
	}
	if field, present := properties["resourceOwnerPassword"]; present && field == nil {
		value.ResourceOwnerPassword = ""
	}
	if field, present := properties["supportState"]; present && field == nil {
		value.SupportState = false
	}
}

func validateAuthorizationServer(value model.AuthorizationServer, creating bool) error {
	if creating && value.DisplayName == "" {
		return errors.New("displayName is required")
	}
	if creating && value.AuthorizationEndpoint == "" {
		return errors.New("authorizationEndpoint is required")
	}
	if creating && value.ClientRegistrationEndpoint == "" {
		return errors.New("clientRegistrationEndpoint is required")
	}
	if creating && value.ClientID == "" {
		return errors.New("clientId is required")
	}
	if creating && len(value.GrantTypes) == 0 {
		return errors.New("grantTypes is required")
	}
	if value.DisplayName == "" {
		return errors.New("displayName cannot be empty")
	}
	if len(value.DisplayName) > 50 {
		return errors.New("displayName must be at most 50 characters")
	}
	if value.AuthorizationEndpoint == "" {
		return errors.New("authorizationEndpoint cannot be empty")
	}
	if value.ClientRegistrationEndpoint == "" {
		return errors.New("clientRegistrationEndpoint cannot be empty")
	}
	if value.ClientID == "" {
		return errors.New("clientId cannot be empty")
	}
	if len(value.GrantTypes) == 0 {
		return errors.New("grantTypes cannot be empty")
	}
	for _, grant := range value.GrantTypes {
		if !authorizationServerGrantTypes[grant] {
			return errors.New("grantTypes must be authorizationCode, implicit, resourceOwnerPassword, or clientCredentials")
		}
	}
	if methods := authorizationServerMethods(value.Document); len(methods) > 0 {
		hasGET := false
		for _, method := range methods {
			if strings.EqualFold(method, http.MethodGet) {
				hasGET = true
				break
			}
		}
		if !hasGET {
			return errors.New("authorizationMethods must include GET")
		}
	}
	return nil
}

func authorizationServerMethods(document map[string]any) []string {
	properties, _ := document["properties"].(map[string]any)
	raw, _ := properties["authorizationMethods"].([]any)
	methods := make([]string, 0, len(raw))
	for _, value := range raw {
		method, _ := value.(string)
		if method != "" {
			methods = append(methods, method)
		}
	}
	return methods
}

func sanitizeAuthorizationServerDocument(document map[string]any) {
	if document == nil {
		return
	}
	delete(document, "clientSecret")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "clientSecret")
}

type documentationPayload struct {
	Properties struct {
		Title   *string `json:"title"`
		Content *string `json:"content"`
	} `json:"properties"`
}

func (h *Handler) documentation(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListDocumentations(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, documentationWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) != 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested documentation resource was not found.", r.URL.Path)
		return
	}
	if rt.Tail[1] == "" || len(rt.Tail[1]) > 256 || !documentationName.MatchString(rt.Tail[1]) {
		writeError(w, http.StatusBadRequest, "ValidationError", "documentationId must be 1-256 characters and must not contain * # & + : < > ?", "documentationId")
		return
	}
	value := model.Documentation{ServiceID: scope, Name: rt.Tail[1]}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetDocumentation(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, documentationWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetDocumentation(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if existingErr == nil {
			value.Name = existing.Name
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, value.ID())
				return
			}
			value = existing
		}
		var body documentationPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = documentationWire(value)
			}
			mergeObject(value.Document, document)
			clearNullDocumentationProperties(&value, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		applyDocumentationPayload(&value, body)
		if err := validateDocumentation(value, r.Method == http.MethodPut); err != nil {
			writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties")
			return
		}
		got, err := h.Store.UpsertDocumentation(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, documentationWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteDocumentation(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func applyDocumentationPayload(value *model.Documentation, body documentationPayload) {
	if body.Properties.Title != nil {
		value.Title = *body.Properties.Title
	}
	if body.Properties.Content != nil {
		value.Content = *body.Properties.Content
	}
}

func clearNullDocumentationProperties(value *model.Documentation, document map[string]any) {
	properties, _ := document["properties"].(map[string]any)
	if field, present := properties["content"]; present && field == nil {
		value.Content = ""
	}
}

func validateDocumentation(value model.Documentation, creating bool) error {
	if creating && value.Title == "" {
		return errors.New("title is required")
	}
	if value.Title == "" {
		return errors.New("title cannot be empty")
	}
	return nil
}

type loggerPayload struct {
	Properties struct {
		LoggerType  *string           `json:"loggerType"`
		Description *string           `json:"description"`
		IsBuffered  *bool             `json:"isBuffered"`
		ResourceID  *string           `json:"resourceId"`
		Credentials map[string]string `json:"credentials"`
	} `json:"properties"`
}

func (h *Handler) logger(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListLoggers(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, loggerWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) != 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested logger resource was not found.", r.URL.Path)
		return
	}
	value := model.Logger{ServiceID: scope, Name: rt.Tail[1], IsBuffered: true}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetLogger(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, loggerWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetLogger(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, value.ID())
				return
			}
			value = existing
		}
		var body loggerPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			mergeObject(value.Document, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		sanitizeLoggerDocument(value.Document)
		applyLoggerPayload(&value, body)
		if value.LoggerType != "applicationInsights" && value.LoggerType != "azureEventHub" && value.LoggerType != "azureMonitor" {
			writeError(w, http.StatusBadRequest, "ValidationError", "loggerType must be applicationInsights, azureEventHub, or azureMonitor.", "properties.loggerType")
			return
		}
		got, err := h.Store.UpsertLogger(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, loggerWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteLogger(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			if errors.Is(err, store.ErrConflict) {
				writeError(w, http.StatusConflict, "ResourceInUse", "The logger is referenced by a diagnostic.", value.ID())
				return
			}
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func applyLoggerPayload(value *model.Logger, body loggerPayload) {
	if body.Properties.LoggerType != nil {
		value.LoggerType = *body.Properties.LoggerType
	}
	if body.Properties.Description != nil {
		value.Description = *body.Properties.Description
	}
	if body.Properties.IsBuffered != nil {
		value.IsBuffered = *body.Properties.IsBuffered
	}
	if body.Properties.ResourceID != nil {
		value.ResourceID = *body.Properties.ResourceID
	}
	if body.Properties.Credentials != nil {
		value.Credentials = body.Properties.Credentials
	}
}

func sanitizeLoggerDocument(document map[string]any) {
	delete(document, "credentials")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "credentials")
}

type diagnosticPayload struct {
	Properties struct {
		LoggerID    *string `json:"loggerId"`
		AlwaysLog   *string `json:"alwaysLog"`
		LogClientIP *bool   `json:"logClientIp"`
		Verbosity   *string `json:"verbosity"`
		Sampling    *struct {
			SamplingType *string  `json:"samplingType"`
			Percentage   *float64 `json:"percentage"`
		} `json:"sampling"`
	} `json:"properties"`
}

func (h *Handler) diagnostic(w http.ResponseWriter, r *http.Request, rt route, scopeID string, tailOffset int) {
	serviceID := model.Service{SubscriptionID: rt.SubscriptionID, ResourceGroup: rt.ResourceGroup, Name: rt.ServiceName}.ID()
	if len(rt.Tail) == tailOffset {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListDiagnostics(scopeID)
		if err != nil {
			h.storeError(w, err, scopeID)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, diagnosticWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) != tailOffset+1 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested diagnostic resource was not found.", r.URL.Path)
		return
	}
	value := model.Diagnostic{ServiceID: serviceID, ScopeID: scopeID, Name: rt.Tail[tailOffset], SamplingType: "fixed", SamplingPercentage: 100}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetDiagnostic(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, diagnosticWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetDiagnostic(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, value.ID())
				return
			}
			value = existing
		}
		var body diagnosticPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			mergeObject(value.Document, document)
			clearNullDiagnosticProperties(&value, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		applyDiagnosticPayload(&value, body)
		if value.LoggerID == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "loggerId is required.", "properties.loggerId")
			return
		}
		logger, err := h.Store.GetLogger(value.LoggerID)
		if err != nil || !strings.EqualFold(logger.ServiceID, serviceID) {
			writeError(w, http.StatusBadRequest, "ValidationError", "loggerId must reference a logger in this service.", "properties.loggerId")
			return
		}
		if value.SamplingType != "fixed" || value.SamplingPercentage < 0 || value.SamplingPercentage > 100 {
			writeError(w, http.StatusBadRequest, "ValidationError", "sampling must use fixed with percentage from 0 through 100.", "properties.sampling")
			return
		}
		if value.AlwaysLog != "" && value.AlwaysLog != "allErrors" {
			writeError(w, http.StatusBadRequest, "ValidationError", "alwaysLog must be allErrors.", "properties.alwaysLog")
			return
		}
		if value.Verbosity != "" && value.Verbosity != "error" && value.Verbosity != "information" && value.Verbosity != "verbose" {
			writeError(w, http.StatusBadRequest, "ValidationError", "verbosity is invalid.", "properties.verbosity")
			return
		}
		got, err := h.Store.UpsertDiagnostic(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, diagnosticWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteDiagnostic(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func applyDiagnosticPayload(value *model.Diagnostic, body diagnosticPayload) {
	if body.Properties.LoggerID != nil {
		value.LoggerID = *body.Properties.LoggerID
	}
	if body.Properties.AlwaysLog != nil {
		value.AlwaysLog = *body.Properties.AlwaysLog
	}
	if body.Properties.LogClientIP != nil {
		value.LogClientIP = *body.Properties.LogClientIP
	}
	if body.Properties.Verbosity != nil {
		value.Verbosity = *body.Properties.Verbosity
	}
	if body.Properties.Sampling != nil {
		if body.Properties.Sampling.SamplingType != nil {
			value.SamplingType = *body.Properties.Sampling.SamplingType
		}
		if body.Properties.Sampling.Percentage != nil {
			value.SamplingPercentage = *body.Properties.Sampling.Percentage
		}
	}
}

func clearNullDiagnosticProperties(value *model.Diagnostic, patch map[string]any) {
	properties, _ := patch["properties"].(map[string]any)
	if field, present := properties["loggerId"]; present && field == nil {
		value.LoggerID = ""
	}
	if field, present := properties["alwaysLog"]; present && field == nil {
		value.AlwaysLog = ""
	}
	if field, present := properties["logClientIp"]; present && field == nil {
		value.LogClientIP = false
	}
	if field, present := properties["verbosity"]; present && field == nil {
		value.Verbosity = ""
	}
	sampling, present := properties["sampling"]
	if present && sampling == nil {
		value.SamplingType, value.SamplingPercentage = "fixed", 100
		return
	}
	samplingObject, _ := sampling.(map[string]any)
	if field, present := samplingObject["samplingType"]; present && field == nil {
		value.SamplingType = "fixed"
	}
	if field, present := samplingObject["percentage"]; present && field == nil {
		value.SamplingPercentage = 100
	}
}

type certificatePayload struct {
	Properties struct {
		Data     []byte  `json:"data"`
		Password *string `json:"password"`
		KeyVault *struct {
			SecretIdentifier *string `json:"secretIdentifier"`
			IdentityClientID *string `json:"identityClientId"`
		} `json:"keyVault"`
	} `json:"properties"`
}

func (h *Handler) certificate(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListCertificates(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, certificateWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) < 2 || len(rt.Tail) > 3 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested certificate resource was not found.", r.URL.Path)
		return
	}
	value := model.Certificate{ServiceID: scope, Name: rt.Tail[1]}
	if len(rt.Tail) == 3 {
		if rt.Tail[2] != "refreshSecret" {
			writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested certificate action was not found.", r.URL.Path)
			return
		}
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		got, err := h.Store.GetCertificate(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if got.KeyVaultSecretID == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "refreshSecret requires a Key Vault-backed certificate.", value.ID())
			return
		}
		h.refreshCertificateSecret(r.Context(), &got)
		updated, err := h.Store.UpsertCertificate(got)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		writeResource(w, http.StatusOK, certificateWire(updated), updated.ETag)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetCertificate(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, certificateWire(got), got.ETag)
	case http.MethodPut:
		_, existingErr := h.Store.GetCertificate(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		var body certificatePayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		value.Document = document
		cleanResourceDocument(value.Document)
		sanitizeCertificateDocument(value.Document)
		if body.Properties.Password != nil {
			value.Password = *body.Properties.Password
		}
		if body.Properties.KeyVault != nil {
			if body.Properties.KeyVault.SecretIdentifier != nil {
				value.KeyVaultSecretID = *body.Properties.KeyVault.SecretIdentifier
			}
			if body.Properties.KeyVault.IdentityClientID != nil {
				value.KeyVaultIdentityID = *body.Properties.KeyVault.IdentityClientID
			}
		}
		value.Data = body.Properties.Data
		if (len(value.Data) == 0) == (value.KeyVaultSecretID == "") {
			writeError(w, http.StatusBadRequest, "ValidationError", "exactly one of data or keyVault.secretIdentifier is required.", "properties")
			return
		}
		if len(value.Data) != 0 {
			leaf, thumbprint, err := certutil.ParsePKCS12(value.Data, value.Password)
			if err != nil {
				writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties.data")
				return
			}
			value.Subject, value.Thumbprint, value.Expiration = leaf.Subject.String(), thumbprint, leaf.NotAfter.UTC()
		} else {
			h.refreshCertificateSecret(r.Context(), &value)
		}
		got, err := h.Store.UpsertCertificate(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		status := http.StatusOK
		if errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, certificateWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteCertificate(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func sanitizeCertificateDocument(document map[string]any) {
	delete(document, "data")
	delete(document, "password")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "data")
	delete(properties, "password")
	delete(properties, "subject")
	delete(properties, "thumbprint")
	delete(properties, "expirationDate")
}

type apiReleasePayload struct {
	Properties struct {
		APIID *string `json:"apiId"`
		Notes *string `json:"notes"`
	} `json:"properties"`
}

func (h *Handler) apiReleaseResource(w http.ResponseWriter, r *http.Request, value model.APIRelease) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetAPIRelease(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, apiReleaseWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetAPIRelease(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, value.ID())
				return
			}
			value = existing
		}
		var body apiReleasePayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = apiReleaseWire(value)
			}
			mergeObject(value.Document, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		if body.Properties.APIID != nil {
			_, targetID, err := h.revisionSource(*body.Properties.APIID)
			if err != nil {
				h.storeError(w, err, *body.Properties.APIID)
				return
			}
			value.TargetAPIID = targetID
		}
		if body.Properties.Notes != nil {
			value.Notes = *body.Properties.Notes
		}
		properties, _ := document["properties"].(map[string]any)
		if field, present := properties["apiId"]; present && field == nil {
			value.TargetAPIID = ""
		}
		if field, present := properties["notes"]; present && field == nil {
			value.Notes = ""
		}
		if value.TargetAPIID == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "apiId is required.", "properties.apiId")
			return
		}
		got, err := h.Store.UpsertAPIRelease(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, apiReleaseWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteAPIRelease(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

type operationPayload struct {
	Properties struct {
		DisplayName *string `json:"displayName"`
		Method      *string `json:"method"`
		URLTemplate *string `json:"urlTemplate"`
	} `json:"properties"`
}

func (h *Handler) operationResource(w http.ResponseWriter, r *http.Request, operation model.Operation) {
	id := operation.APIID + "/operations/" + operation.Name
	switch r.Method {
	case http.MethodGet:
		got, err := h.Store.GetOperation(id)
		if err != nil {
			h.storeError(w, err, id)
			return
		}
		writeResource(w, http.StatusOK, operationWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetOperation(id)
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, id)
			return
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, id)
				return
			}
			operation = existing
		}
		var body operationPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if operation.Document == nil {
				operation.Document = operationWire(operation)
			}
			mergeObject(operation.Document, document)
		} else {
			operation.Document = document
		}
		cleanResourceDocument(operation.Document)
		applyOperationPayload(&operation, body)
		if operation.Method == "" || operation.URLTemplate == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "method and urlTemplate are required.", "properties")
			return
		}
		got, err := h.Store.UpsertOperation(operation)
		if err != nil {
			h.storeError(w, err, id)
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), id)
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, operationWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteOperation(id); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, id)
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), id)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func applyOperationPayload(operation *model.Operation, body operationPayload) {
	if body.Properties.DisplayName != nil {
		operation.DisplayName = *body.Properties.DisplayName
	}
	if body.Properties.Method != nil {
		operation.Method = *body.Properties.Method
	}
	if body.Properties.URLTemplate != nil {
		operation.URLTemplate = *body.Properties.URLTemplate
	}
}

func cleanResourceDocument(document map[string]any) {
	delete(document, "id")
	delete(document, "name")
	delete(document, "type")
	delete(document, "etag")
}

func (h *Handler) product(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListProducts(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, productWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources})
		return
	}
	product := model.Product{ServiceID: scope, Name: rt.Tail[1]}
	if len(rt.Tail) == 2 {
		h.productResource(w, r, product)
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "apis") {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		ids, err := h.Store.ListProductAPIs(product.ID())
		if err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		resources := make([]map[string]any, 0, len(ids))
		for _, id := range ids {
			api, err := h.Store.GetAPI(id)
			if err != nil {
				h.storeError(w, err, id)
				return
			}
			resources = append(resources, apiWire(api))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources})
		return
	}
	if (len(rt.Tail) == 3 || len(rt.Tail) == 4) && isLinkSegment(rt.Tail[2], "apiLinks", "groupLinks") {
		if _, err := h.Store.GetProduct(product.ID()); err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		surface, err := h.productLinkSurface(product, rt.Tail[2])
		if err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		surface.armType = linkType(rt.Workspace != "", "products", rt.Tail[2])
		name := ""
		if len(rt.Tail) == 4 {
			name = rt.Tail[3]
		}
		h.linkRoute(w, r, surface, name)
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "tags") {
		if _, err := h.Store.GetProduct(product.ID()); err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		h.resourceTagCollection(w, r, product.ID())
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "groups") {
		if _, err := h.Store.GetProduct(product.ID()); err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListProductGroups(product.ID())
		if err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, groupWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "apis") {
		apiID := scope + "/apis/" + rt.Tail[3]
		switch r.Method {
		case http.MethodPut:
			if err := h.Store.LinkProductAPI(product.ID(), apiID); err != nil {
				h.storeError(w, err, product.ID())
				return
			}
			if err := h.activate(); err != nil {
				writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), product.ID())
				return
			}
			writeResource(w, http.StatusCreated, productAPIWire(product.ID(), rt.Tail[3]), "")
		case http.MethodDelete:
			if err := h.Store.UnlinkProductAPI(product.ID(), apiID); err != nil && !errors.Is(err, store.ErrNotFound) {
				h.storeError(w, err, product.ID())
				return
			}
			if err := h.activate(); err != nil {
				writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), product.ID())
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w)
		}
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "tags") {
		if _, err := h.Store.GetProduct(product.ID()); err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		h.resourceTag(w, r, scope, product.ID(), rt.Tail[3])
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "groups") {
		if _, err := h.Store.GetProduct(product.ID()); err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		group := model.Group{ServiceID: scope, Name: rt.Tail[3]}
		got, err := h.Store.GetGroup(group.ID())
		if err != nil {
			h.storeError(w, err, group.ID())
			return
		}
		exists, err := h.Store.HasProductGroup(product.ID(), group.ID())
		if err != nil {
			h.storeError(w, err, group.ID())
			return
		}
		switch r.Method {
		case http.MethodGet:
			if !exists {
				h.storeError(w, store.ErrNotFound, group.ID())
				return
			}
			writeResource(w, http.StatusOK, groupWire(got), got.ETag)
		case http.MethodHead:
			if !exists {
				h.storeError(w, store.ErrNotFound, group.ID())
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodPut:
			if err := h.Store.LinkProductGroup(product.ID(), group.ID()); err != nil {
				h.storeError(w, err, group.ID())
				return
			}
			status := http.StatusCreated
			if exists {
				status = http.StatusOK
			}
			writeResource(w, status, groupWire(got), got.ETag)
		case http.MethodDelete:
			if err := h.Store.UnlinkProductGroup(product.ID(), group.ID()); err != nil {
				h.storeError(w, err, group.ID())
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w)
		}
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "policies") && equal(rt.Tail[3], "policy") {
		if _, err := h.Store.GetProduct(product.ID()); err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		h.policyResource(w, r, product.ID(), "Microsoft.ApiManagement/service/products/policies")
		return
	}
	writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested product resource was not found.", r.URL.Path)
}

type productPayload struct {
	Properties struct {
		DisplayName      *string `json:"displayName"`
		State            *string `json:"state"`
		ApprovalRequired *bool   `json:"approvalRequired"`
	} `json:"properties"`
}

func (h *Handler) productResource(w http.ResponseWriter, r *http.Request, product model.Product) {
	switch r.Method {
	case http.MethodGet:
		got, err := h.Store.GetProduct(product.ID())
		if err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		writeResource(w, http.StatusOK, productWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetProduct(product.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, product.ID())
			return
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, product.ID())
				return
			}
			product = existing
		} else {
			product.State = "notPublished"
		}
		var body productPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if product.Document == nil {
				product.Document = productWire(product)
			}
			mergeObject(product.Document, document)
		} else {
			product.Document = document
		}
		cleanResourceDocument(product.Document)
		applyProductPayload(&product, body)
		if product.DisplayName == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "displayName is required.", "properties.displayName")
			return
		}
		got, err := h.Store.UpsertProduct(product)
		if err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), product.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, productWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteProduct(product.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, product.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), product.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func applyProductPayload(product *model.Product, body productPayload) {
	if body.Properties.DisplayName != nil {
		product.DisplayName = *body.Properties.DisplayName
	}
	if body.Properties.State != nil {
		product.State = *body.Properties.State
	}
	if body.Properties.ApprovalRequired != nil {
		product.ApprovalRequired = *body.Properties.ApprovalRequired
	}
}

func (h *Handler) subscription(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListSubscriptions(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, subscriptionWire(value, false))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources})
		return
	}
	value := model.Subscription{ServiceID: scope, Name: rt.Tail[1]}
	if len(rt.Tail) == 2 {
		h.subscriptionResource(w, r, value)
		return
	}
	if len(rt.Tail) != 3 || r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested subscription resource was not found.", r.URL.Path)
		return
	}
	switch rt.Tail[2] {
	case "listSecrets":
		got, err := h.Store.GetSubscription(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		writeResource(w, http.StatusOK, subscriptionSecretsWire(got), got.ETag)
	case "regeneratePrimaryKey", "regenerateSecondaryKey":
		got, err := h.Store.RegenerateSubscriptionKey(value.ID(), rt.Tail[2] == "regeneratePrimaryKey")
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		w.Header().Set("ETag", got.ETag)
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested subscription action was not found.", r.URL.Path)
	}
}

type subscriptionPayload struct {
	Properties struct {
		DisplayName  *string `json:"displayName"`
		Scope        *string `json:"scope"`
		State        *string `json:"state"`
		PrimaryKey   *string `json:"primaryKey"`
		SecondaryKey *string `json:"secondaryKey"`
	} `json:"properties"`
}

func (h *Handler) subscriptionResource(w http.ResponseWriter, r *http.Request, value model.Subscription) {
	switch r.Method {
	case http.MethodGet:
		got, err := h.Store.GetSubscription(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		writeResource(w, http.StatusOK, subscriptionWire(got, false), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetSubscription(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if r.Method == http.MethodPatch && errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if existingErr == nil {
			value = existing
		}
		var body subscriptionPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			// The store guarantees a document to merge into, including for a
			// subscription stored before documents were written.
			mergeObject(value.Document, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		sanitizeSubscriptionDocument(value.Document)
		applySubscriptionPayload(&value, body)
		clearNullSubscriptionProperties(&value, document)
		if value.DisplayName == "" || value.Scope == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "displayName and scope are required.", "properties")
			return
		}
		got, err := h.Store.UpsertSubscription(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, subscriptionWire(got, false), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteSubscription(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func applySubscriptionPayload(value *model.Subscription, body subscriptionPayload) {
	if body.Properties.DisplayName != nil {
		value.DisplayName = *body.Properties.DisplayName
	}
	if body.Properties.Scope != nil {
		value.Scope = *body.Properties.Scope
	}
	if body.Properties.State != nil {
		value.State = *body.Properties.State
	}
	if body.Properties.PrimaryKey != nil {
		value.PrimaryKey = *body.Properties.PrimaryKey
	}
	if body.Properties.SecondaryKey != nil {
		value.SecondaryKey = *body.Properties.SecondaryKey
	}
}

func sanitizeSubscriptionDocument(document map[string]any) {
	delete(document, "primaryKey")
	delete(document, "secondaryKey")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "primaryKey")
	delete(properties, "secondaryKey")
}

func clearNullSubscriptionProperties(value *model.Subscription, patch map[string]any) {
	properties, _ := patch["properties"].(map[string]any)
	if field, present := properties["displayName"]; present && field == nil {
		value.DisplayName = ""
	}
	if field, present := properties["scope"]; present && field == nil {
		value.Scope = ""
	}
	if field, present := properties["state"]; present && field == nil {
		value.State = ""
	}
}

func (h *Handler) activate() error {
	if h.Activate == nil {
		return nil
	}
	return h.Activate()
}
func (h *Handler) storeError(w http.ResponseWriter, err error, target string) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The resource was not found.", target)
	} else {
		writeError(w, http.StatusConflict, "Conflict", err.Error(), target)
	}
}

// OperationStatus serves deterministic completed LRO polling.
func OperationStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "Succeeded"})
}

func serviceWire(v model.Service) map[string]any {
	result := cloneObject(v.Document)
	result["id"] = v.ID()
	result["name"] = v.Name
	result["type"] = "Microsoft.ApiManagement/service"
	result["location"] = v.Location
	result["etag"] = v.ETag
	result["sku"] = map[string]any{"name": v.SKUName, "capacity": v.SKUCapacity}
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["publisherName"] = v.PublisherName
	properties["publisherEmail"] = v.PublisherEmail
	properties["provisioningState"] = v.ProvisioningState
	properties["gatewayUrl"] = "https://" + v.Name + ".azure-api.localhost"
	properties["gatewayRegionalUrl"] = "https://" + v.Name + ".azure-api.localhost"
	properties["developerPortalUrl"] = "https://" + v.Name + ".portal.azure-api.localhost"
	properties["portalUrl"] = "https://" + v.Name + ".portal.azure-api.localhost"
	properties["managementApiUrl"] = "https://" + v.Name + ".management.azure-api.localhost"
	properties["scmUrl"] = "https://" + v.Name + ".scm.azure-api.localhost"
	return result
}
func apiWire(v model.API) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/apis"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	delete(properties, "format")
	delete(properties, "value")
	delete(properties, "sourceApiId")
	properties["displayName"], properties["path"], properties["serviceUrl"] = v.DisplayName, v.Path, v.ServiceURL
	properties["protocols"], properties["subscriptionRequired"] = v.Protocols, v.SubscriptionRequired
	properties["apiRevision"], properties["apiRevisionDescription"], properties["isCurrent"] = v.Revision, v.RevisionDescription, v.IsCurrent
	if v.Version != "" {
		properties["apiVersion"] = v.Version
	} else {
		delete(properties, "apiVersion")
	}
	if v.VersionSetID != "" {
		properties["apiVersionSetId"] = v.VersionSetID
	} else {
		delete(properties, "apiVersionSetId")
	}
	return result
}
func apiVersionSetWire(v model.APIVersionSet) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/apiVersionSets"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["displayName"], properties["versioningScheme"] = v.DisplayName, v.VersioningScheme
	properties["versionHeaderName"], properties["versionQueryName"] = v.VersionHeaderName, v.VersionQueryName
	properties["description"] = v.Description
	return result
}
func (h *Handler) secretRetriever() keyvault.Retriever {
	if h.Secrets != nil {
		return h.Secrets
	}
	client := h.KeyVaultClient
	if client == nil {
		client = h.ImportClient
	}
	return keyvault.HTTP{Client: client, AcquireToken: h.AcquireToken, ClientID: h.IdentityClientID, ClientSecret: h.IdentityClientSecret}
}

func (h *Handler) keyVaultNow() time.Time {
	if h.Store != nil && h.Store.Clock != nil {
		return time.Unix(h.Store.Clock.Now(), 0).UTC()
	}
	return time.Now().UTC()
}

func (h *Handler) refreshNamedValueSecret(ctx context.Context, value *model.NamedValue) {
	secret, err := h.secretRetriever().GetSecret(ctx, value.KeyVaultSecretID)
	value.KeyVaultStatusCode, value.KeyVaultStatusMessage = keyvault.Classify(err)
	value.KeyVaultStatusTime = h.keyVaultNow()
	if err == nil {
		value.Value = secret.Value
	}
}

func (h *Handler) refreshCertificateSecret(ctx context.Context, value *model.Certificate) {
	secret, err := h.secretRetriever().GetSecret(ctx, value.KeyVaultSecretID)
	value.KeyVaultStatusCode, value.KeyVaultStatusMessage = keyvault.Classify(err)
	value.KeyVaultStatusTime = h.keyVaultNow()
	if err != nil {
		return
	}
	data := decodeKeyVaultCertificate(secret.Value)
	leaf, thumbprint, parseErr := certutil.ParsePKCS12(data, value.Password)
	if parseErr != nil {
		value.KeyVaultStatusCode, value.KeyVaultStatusMessage = "Error", parseErr.Error()
		return
	}
	value.Data, value.Subject, value.Thumbprint, value.Expiration = data, leaf.Subject.String(), thumbprint, leaf.NotAfter.UTC()
}

func decodeKeyVaultCertificate(value string) []byte {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return []byte(value)
	}
	return data
}

func keyVaultWire(secretID, identityID, code, message string, at time.Time) map[string]any {
	result := map[string]any{"secretIdentifier": secretID, "identityClientId": identityID}
	if code == "" && message == "" && at.IsZero() {
		return result
	}
	status := map[string]any{"code": code, "message": message}
	if !at.IsZero() {
		status["timeStampUtc"] = at.UTC().Format(time.RFC3339)
	}
	result["lastStatus"] = status
	return result
}

func namedValueWire(v model.NamedValue) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/namedValues"
	delete(result, "value")
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	delete(properties, "value")
	properties["displayName"], properties["secret"], properties["tags"] = v.DisplayName, v.Secret, v.Tags
	if v.KeyVaultSecretID != "" {
		properties["keyVault"] = keyVaultWire(v.KeyVaultSecretID, v.KeyVaultIdentityID, v.KeyVaultStatusCode, v.KeyVaultStatusMessage, v.KeyVaultStatusTime)
	} else {
		delete(properties, "keyVault")
	}
	return result
}
func backendWire(v model.Backend) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/backends"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["title"], properties["description"], properties["url"] = v.Title, v.Description, v.URL
	properties["protocol"], properties["resourceId"] = v.Protocol, v.ResourceID
	return result
}
func certificateWire(v model.Certificate) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/certificates"
	delete(result, "data")
	delete(result, "password")
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	for _, field := range []string{"data", "password", "subject", "thumbprint", "expirationDate", "keyVault"} {
		delete(properties, field)
	}
	if v.Subject != "" {
		properties["subject"] = v.Subject
	}
	if v.Thumbprint != "" {
		properties["thumbprint"] = v.Thumbprint
	}
	if !v.Expiration.IsZero() {
		properties["expirationDate"] = v.Expiration.UTC().Format(time.RFC3339)
	}
	if v.KeyVaultSecretID != "" {
		properties["keyVault"] = keyVaultWire(v.KeyVaultSecretID, v.KeyVaultIdentityID, v.KeyVaultStatusCode, v.KeyVaultStatusMessage, v.KeyVaultStatusTime)
	}
	return result
}
func apiRevisionWire(v model.API) map[string]any {
	base, _ := splitAPIRevision(v.Name)
	apiID := model.API{ServiceID: v.ServiceID, Name: base + ";rev=" + v.Revision}.ID()
	return map[string]any{"apiId": apiID, "apiRevision": v.Revision, "description": v.RevisionDescription,
		"createdDateTime": time.Unix(v.CreatedAt, 0).UTC().Format(time.RFC3339),
		"updatedDateTime": time.Unix(v.UpdatedAt, 0).UTC().Format(time.RFC3339), "isOnline": true, "isCurrent": v.IsCurrent}
}
func apiReleaseWire(v model.APIRelease) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/apis/releases"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["apiId"], properties["notes"] = v.TargetAPIID, v.Notes
	properties["createdDateTime"] = time.Unix(v.CreatedAt, 0).UTC().Format(time.RFC3339)
	properties["updatedDateTime"] = time.Unix(v.UpdatedAt, 0).UTC().Format(time.RFC3339)
	return result
}
func operationWire(v model.Operation) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.APIID+"/operations/"+v.Name, v.Name, "Microsoft.ApiManagement/service/apis/operations"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["displayName"], properties["method"], properties["urlTemplate"] = v.DisplayName, v.Method, v.URLTemplate
	return result
}
func apiSchemaWire(v model.APISchema) map[string]any {
	result := cloneObject(v.ARMDocument)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/apis/schemas"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["contentType"], properties["document"] = v.ContentType, v.Document
	return result
}
func tagWire(v model.Tag) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/tags"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["displayName"] = v.DisplayName
	return result
}
func groupWire(v model.Group) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/groups"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["displayName"], properties["description"], properties["type"] = v.DisplayName, v.Description, v.Type
	properties["externalId"], properties["builtIn"] = nullableString(v.ExternalID), v.BuiltIn
	return result
}
func userWire(v model.User) map[string]any {
	identities := make([]map[string]any, 0, len(v.Identities))
	for _, identity := range v.Identities {
		identities = append(identities, map[string]any{"provider": identity.Provider, "id": identity.ID})
	}
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/users"
	delete(result, "password")
	delete(result, "primaryKey")
	delete(result, "secondaryKey")
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	delete(properties, "password")
	delete(properties, "primaryKey")
	delete(properties, "secondaryKey")
	properties["firstName"], properties["lastName"], properties["email"] = v.FirstName, v.LastName, v.Email
	properties["state"], properties["note"], properties["identities"] = v.State, v.Note, identities
	properties["registrationDate"] = time.Unix(v.RegistrationAt, 0).UTC().Format(time.RFC3339)
	return result
}
func sanitizeUserDocument(document map[string]any) {
	delete(document, "password")
	delete(document, "primaryKey")
	delete(document, "secondaryKey")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "password")
	delete(properties, "primaryKey")
	delete(properties, "secondaryKey")
}
func clearNullUserProperties(value *model.User, patch map[string]any) {
	properties, _ := patch["properties"].(map[string]any)
	if field, present := properties["firstName"]; present && field == nil {
		value.FirstName = ""
	}
	if field, present := properties["lastName"]; present && field == nil {
		value.LastName = ""
	}
	if field, present := properties["email"]; present && field == nil {
		value.Email = ""
	}
	if field, present := properties["state"]; present && field == nil {
		value.State = ""
	}
	if field, present := properties["note"]; present && field == nil {
		value.Note = ""
	}
	if field, present := properties["identities"]; present && field == nil {
		value.Identities = nil
	}
}
func policyFragmentWire(v model.PolicyFragment, format string) map[string]any {
	if format != "xml" && format != "rawxml" {
		format = v.Format
	}
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/policyFragments"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["description"], properties["format"], properties["value"] = v.Description, format, v.Value
	properties["provisioningState"] = v.ProvisioningState
	return result
}
func cacheWire(v model.Cache) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/caches"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["connectionString"] = cacheConnectionReference(v.ConnectionString)
	properties["useFromLocation"] = v.UseFromLocation
	properties["description"] = v.Description
	properties["resourceId"] = v.ResourceID
	properties["region"] = v.UseFromLocation
	return result
}

func documentationWire(v model.Documentation) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/documentations"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["title"] = v.Title
	properties["content"] = v.Content
	return result
}

func authorizationServerWire(v model.AuthorizationServer) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/authorizationServers"
	delete(result, "clientSecret")
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	delete(properties, "clientSecret")
	grants := v.GrantTypes
	if grants == nil {
		grants = []string{}
	}
	properties["displayName"] = v.DisplayName
	properties["description"] = v.Description
	properties["authorizationEndpoint"] = v.AuthorizationEndpoint
	properties["clientRegistrationEndpoint"] = v.ClientRegistrationEndpoint
	properties["clientId"] = v.ClientID
	properties["tokenEndpoint"] = v.TokenEndpoint
	properties["defaultScope"] = v.DefaultScope
	properties["resourceOwnerUsername"] = v.ResourceOwnerUsername
	properties["resourceOwnerPassword"] = v.ResourceOwnerPassword
	properties["supportState"] = v.SupportState
	properties["grantTypes"] = grants
	return result
}

func openIDConnectProviderWire(v model.OpenIDConnectProvider) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/openidConnectProviders"
	delete(result, "clientSecret")
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	delete(properties, "clientSecret")
	properties["displayName"] = v.DisplayName
	properties["description"] = v.Description
	properties["metadataEndpoint"] = v.MetadataEndpoint
	properties["clientId"] = v.ClientID
	return result
}

func identityProviderWire(v model.IdentityProvider) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/identityProviders"
	delete(result, "clientSecret")
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	delete(properties, "clientSecret")
	tenants := v.AllowedTenants
	if tenants == nil {
		tenants = []string{}
	}
	properties["type"] = v.Name
	properties["clientId"] = v.ClientID
	properties["allowedTenants"] = tenants
	properties["authority"] = v.Authority
	properties["signinTenant"] = v.SigninTenant
	properties["signupPolicyName"] = v.SignupPolicyName
	properties["signinPolicyName"] = v.SigninPolicyName
	properties["profileEditingPolicyName"] = v.ProfileEditingPolicyName
	properties["passwordResetPolicyName"] = v.PasswordResetPolicyName
	return result
}

func cacheConnectionReference(value string) string {
	if strings.HasPrefix(value, "{{") && strings.HasSuffix(value, "}}") {
		return value
	}
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("{{Cache-ConnectionString-%x}}", digest[:8])
}

func loggerWire(v model.Logger) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/loggers"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["loggerType"], properties["description"] = v.LoggerType, v.Description
	properties["isBuffered"], properties["resourceId"], properties["credentials"] = v.IsBuffered, v.ResourceID, loggerCredentialReferences(v.Credentials)
	return result
}
func loggerCredentialReferences(credentials map[string]string) map[string]string {
	result := make(map[string]string, len(credentials))
	for name, value := range credentials {
		if strings.HasPrefix(value, "{{") && strings.HasSuffix(value, "}}") {
			result[name] = value
			continue
		}
		digest := sha256.Sum256([]byte(value))
		result[name] = fmt.Sprintf("{{Logger-Credentials-%x}}", digest[:8])
	}
	return result
}
func diagnosticWire(v model.Diagnostic) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"] = v.ID(), v.Name
	result["type"] = "Microsoft.ApiManagement/service/diagnostics"
	if !strings.EqualFold(v.ScopeID, v.ServiceID) {
		result["type"] = "Microsoft.ApiManagement/service/apis/diagnostics"
	}
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["loggerId"], properties["alwaysLog"] = v.LoggerID, v.AlwaysLog
	properties["logClientIp"], properties["verbosity"] = v.LogClientIP, v.Verbosity
	properties["sampling"] = map[string]any{"samplingType": v.SamplingType, "percentage": v.SamplingPercentage}
	return result
}
func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
func productWire(v model.Product) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/products"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["displayName"], properties["state"], properties["approvalRequired"] = v.DisplayName, v.State, v.ApprovalRequired
	if _, present := properties["subscriptionRequired"]; !present {
		properties["subscriptionRequired"] = true
	}
	return result
}
func productAPIWire(productID, apiName string) map[string]any {
	return map[string]any{"id": productID + "/apis/" + apiName, "name": apiName, "type": "Microsoft.ApiManagement/service/products/apis"}
}
func subscriptionWire(v model.Subscription, secrets bool) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/subscriptions"
	delete(result, "primaryKey")
	delete(result, "secondaryKey")
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	delete(properties, "primaryKey")
	delete(properties, "secondaryKey")
	properties["displayName"], properties["scope"], properties["state"] = v.DisplayName, v.Scope, v.State
	if secrets {
		properties["primaryKey"], properties["secondaryKey"] = v.PrimaryKey, v.SecondaryKey
	}
	return result
}
func subscriptionSecretsWire(v model.Subscription) map[string]any {
	return map[string]any{"primaryKey": v.PrimaryKey, "secondaryKey": v.SecondaryKey}
}
func (h *Handler) policyResource(w http.ResponseWriter, r *http.Request, scopeID, armType string) {
	switch r.Method {
	case http.MethodGet:
		value, err := h.Store.GetPolicy(scopeID)
		if err != nil {
			h.storeError(w, err, scopeID)
			return
		}
		writeResource(w, http.StatusOK, policyWire(scopeID, armType, value), value.ETag)
	case http.MethodPut:
		var body struct {
			Properties struct {
				Format string `json:"format"`
				Value  string `json:"value"`
			} `json:"properties"`
		}
		if err := decode(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		// A resolver's policy is a different document: its root is
		// <http-data-source>, not <policies>. Validating it as a policy would
		// reject every resolver Azure's own portal produces.
		validate := h.ValidatePolicy
		if strings.HasSuffix(armType, "/resolvers/policies") {
			validate = h.ValidateResolverPolicy
		}
		if validate != nil {
			if err := validate(body.Properties.Value); err != nil {
				writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties.value")
				return
			}
		}
		value, err := h.Store.UpsertPolicy(model.Policy{ScopeID: scopeID, Format: body.Properties.Format, Value: body.Properties.Value})
		if err != nil {
			h.storeError(w, err, scopeID)
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), scopeID)
			return
		}
		writeResource(w, http.StatusCreated, policyWire(scopeID, armType, value), value.ETag)
	default:
		methodNotAllowed(w)
	}
}

func policyWire(scopeID, armType string, value model.Policy) map[string]any {
	return map[string]any{"id": scopeID + "/policies/policy", "name": "policy", "type": armType, "properties": map[string]any{"format": value.Format, "value": value.Value}}
}

func decode(r *http.Request, value any) error {
	if err := json.NewDecoder(r.Body).Decode(value); err != nil {
		return fmt.Errorf("malformed request body: %w", err)
	}
	return nil
}
func decodeDocument(r *http.Request, value any, document *map[string]any) error {
	if err := json.NewDecoder(r.Body).Decode(document); err != nil {
		return fmt.Errorf("malformed request body: %w", err)
	}
	encoded, _ := json.Marshal(*document)
	_ = json.Unmarshal(encoded, value)
	return nil
}
func mergeObject(target, patch map[string]any) {
	for key, value := range patch {
		if value == nil {
			delete(target, key)
			continue
		}
		patchObject, patchIsObject := value.(map[string]any)
		targetObject, targetIsObject := target[key].(map[string]any)
		if patchIsObject && targetIsObject {
			mergeObject(targetObject, patchObject)
			continue
		}
		target[key] = value
	}
}
func cloneObject(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		if object, ok := value.(map[string]any); ok {
			result[key] = cloneObject(object)
			continue
		}
		result[key] = value
	}
	return result
}
func writeResource(w http.ResponseWriter, status int, value any, etag string) {
	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	writeJSON(w, status, value)
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, code, message, target string) {
	w.Header().Set("x-ms-error-code", code)
	errorValue := map[string]any{"code": code, "message": message}
	if target != "" {
		errorValue["target"] = target
	}
	if code == "ValidationError" && target != "" {
		errorValue["details"] = []map[string]any{{"code": code, "message": message, "target": target}}
	}
	writeJSON(w, status, map[string]any{"error": errorValue})
}
func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "The HTTP method is not allowed for this resource.", "")
}
func absolute(r *http.Request, path string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		scheme = forwarded
	}
	return scheme + "://" + r.Host + path
}
func split(path string) []string {
	value := strings.Trim(path, "/")
	if value == "" {
		return nil
	}
	return strings.Split(value, "/")
}
func equal(a, b string) bool { return strings.EqualFold(a, b) }
func splitAPIRevision(name string) (string, string) {
	index := strings.LastIndex(strings.ToLower(name), ";rev=")
	if index < 0 {
		return name, "1"
	}
	return name[:index], name[index+5:]
}

// isGraphQLAPIDocument reports whether an API payload declares the graphql type.
//
// Both spellings are accepted: `type` is the wire name Azure's contract uses
// and what Microsoft's SDK sends, `apiType` is what raw ARM callers here have
// written. Accepting only one silently ignores half the callers.
func isGraphQLAPIDocument(document map[string]any) bool {
	properties, _ := document["properties"].(map[string]any)
	declared, _ := properties["type"].(string)
	if declared == "" {
		declared, _ = properties["apiType"].(string)
	}
	return strings.EqualFold(declared, "graphql")
}

// isWSDLFormat reports whether an import format carries a WSDL document.
func isWSDLFormat(format string) bool {
	return strings.EqualFold(format, "wsdl") || strings.EqualFold(format, "wsdl-link")
}

// markSOAPAPIType stamps the soap type on an imported WSDL API, which is what
// Azure does and what puts the API on the gateway's SOAP path.
//
// Stamped as `type`, the name Azure's REST contract uses, so a caller reading
// the API back with Microsoft's SDK sees the type it expects. Stamping the
// emulator's older `apiType` spelling instead left an imported SOAP API
// reporting no type at all to that SDK.
func markSOAPAPIType(document map[string]any) {
	properties, ok := document["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		document["properties"] = properties
	}
	properties["type"] = "soap"
}

// wsdlOperations renders a WSDL's operations as APIM operations.
//
// Every SOAP operation is a POST to the same URL; the operation is chosen by
// SOAPAction or by the body element, not by the path. Giving them distinct
// URL templates would invent a REST shape the WSDL does not describe.
func wsdlOperations(schema *soapc.Schema) []model.Operation {
	operations := make([]model.Operation, 0)
	for _, operation := range schema.Operations() {
		operations = append(operations, model.Operation{
			Name: operation.Name, DisplayName: operation.Name,
			Method: http.MethodPost, URLTemplate: "/",
			Document: map[string]any{"properties": map[string]any{"soapAction": operation.Action}},
		})
	}
	return operations
}

// requireScope reports whether the route's parent exists: the workspace when
// the path named one, otherwise the service.
func (h *Handler) requireScope(rt route) error {
	if rt.Workspace != "" {
		_, err := h.Store.GetWorkspace(rt.scopeID())
		return err
	}
	_, err := h.Store.GetService(rt.service().ID())
	return err
}

// authorizationProviderRoute dispatches the credential-manager resource tree:
// providers, the credentials under them, and each credential's access policies.
func (h *Handler) authorizationProviderRoute(w http.ResponseWriter, r *http.Request, rt route) {
	serviceID := rt.service().ID()
	switch len(rt.Tail) {
	case 1:
		h.authorizationProviderCollection(w, r, serviceID)
	case 2:
		h.authorizationProviderResource(w, r, model.AuthorizationProvider{ServiceID: serviceID, Name: rt.Tail[1]})
	case 3, 4, 5, 6:
		providerID := serviceID + "/authorizationProviders/" + rt.Tail[1]
		if !equal(rt.Tail[2], "authorizations") {
			writeError(w, http.StatusNotFound, "ResourceNotFound", "The resource was not found.", providerID)
			return
		}
		h.authorizationRoute(w, r, rt, providerID)
	default:
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The resource was not found.", serviceID)
	}
}

func (h *Handler) authorizationRoute(w http.ResponseWriter, r *http.Request, rt route, providerID string) {
	// The provider must exist before anything beneath it is addressable,
	// otherwise a typo in the provider name silently creates a credential under
	// a provider nobody configured.
	if _, err := h.Store.GetAuthorizationProvider(providerID); err != nil {
		h.storeError(w, err, providerID)
		return
	}
	switch len(rt.Tail) {
	case 3:
		h.authorizationCollection(w, r, providerID)
		return
	case 4:
		h.authorizationResource(w, r, model.Authorization{ProviderID: providerID, Name: rt.Tail[3]})
		return
	}
	authorizationID := providerID + "/authorizations/" + rt.Tail[3]
	if len(rt.Tail) == 5 && !equal(rt.Tail[4], "accessPolicies") {
		h.authorizationAction(w, r, model.Authorization{ProviderID: providerID, Name: rt.Tail[3]}, rt.Tail[4])
		return
	}
	if len(rt.Tail) == 5 && equal(rt.Tail[4], "accessPolicies") {
		if _, err := h.Store.GetAuthorization(authorizationID); err != nil {
			h.storeError(w, err, authorizationID)
			return
		}
		h.accessPolicyCollection(w, r, authorizationID)
		return
	}
	if len(rt.Tail) == 6 && equal(rt.Tail[4], "accessPolicies") {
		if _, err := h.Store.GetAuthorization(authorizationID); err != nil {
			h.storeError(w, err, authorizationID)
			return
		}
		h.accessPolicyResource(w, r, model.AuthorizationAccessPolicy{AuthorizationID: authorizationID, Name: rt.Tail[5]})
		return
	}
	writeError(w, http.StatusNotFound, "ResourceNotFound", "The resource was not found.", authorizationID)
}
