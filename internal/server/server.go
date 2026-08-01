// Package server assembles management, gateway, persistence, and control APIs.
package server

import (
	"encoding/json"
	"errors"
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
	mux     *http.ServeMux
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
	s := &Server{Cfg: cfg, Clock: ck, Store: st, Gateway: runtime, mux: http.NewServeMux()}
	s.ARM = &arm.Handler{
		Store: st, Auth: validator,
		Activate:       func() error { return runtime.Activate(st, cfg.StrictPolicies) },
		ValidatePolicy: func(value string) error { _, err := policy.Compile(value, cfg.StrictPolicies); return err },
		ImportClient:   backendClient,
		ExportKey:      []byte(store.NewOpaqueID()),
	}
	seed := model.Service{SubscriptionID: defaultSubscription, ResourceGroup: defaultResourceGroup, Name: cfg.DefaultService, Location: cfg.Location, SKUName: "Developer", SKUCapacity: 1, PublisherName: "Local Emulator", PublisherEmail: "local@azure-apim-emulator.test"}
	if _, err := st.GetService(seed.ID()); errors.Is(err, store.ErrNotFound) {
		if _, err := st.UpsertService(seed); err != nil {
			st.Close()
			return nil, err
		}
	} else if err != nil {
		st.Close()
		return nil, err
	}
	if err := runtime.Activate(st, cfg.StrictPolicies); err != nil {
		st.Close()
		return nil, err
	}
	s.register()
	return s, nil
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler { return s.mux }

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
				"certificates": countCertificates(s.Store, service.ID()), "tags": countTags(s.Store, service.ID()),
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

func countAPIVersionSets(st *store.Store, id string) int {
	v, _ := st.ListAPIVersionSets(id)
	return len(v)
}
func countNamedValues(st *store.Store, id string) int { v, _ := st.ListNamedValues(id); return len(v) }
func countBackends(st *store.Store, id string) int    { v, _ := st.ListBackends(id); return len(v) }
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
<style>body{font:15px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#17202a;background:#f6f8fa}main{background:#fff;border:1px solid #d0d7de;padding:1.25rem;border-radius:8px}h1{margin-top:0}pre{background:#f6f8fa;padding:1rem;overflow:auto}button{padding:.55rem .8rem;border:1px solid #8c959f;border-radius:6px;background:#fff;cursor:pointer}</style></head>
<body><main><h1>Azure APIM Emulator</h1><p id="summary">Loading runtime state...</p><button id="refresh">Refresh</button><pre id="state"></pre></main>
<script>async function load(){const r=await fetch('/_emulator/portal/api/status');const v=await r.json();document.querySelector('#summary').textContent=v.service+' | clock '+v.clock.now;document.querySelector('#state').textContent=JSON.stringify(v,null,2)}document.querySelector('#refresh').addEventListener('click',load);load();</script></body></html>`

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
