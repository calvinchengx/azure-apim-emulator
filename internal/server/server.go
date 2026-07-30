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
	s := &Server{Cfg: cfg, Clock: ck, Store: st, Gateway: runtime, mux: http.NewServeMux()}
	s.ARM = &arm.Handler{
		Store: st, Auth: validator,
		Activate:       func() error { return runtime.Activate(st, cfg.StrictPolicies) },
		ValidatePolicy: func(value string) error { _, err := policy.Compile(value, cfg.StrictPolicies); return err },
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
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(strings.ToLower(r.URL.Path), "/subscriptions/") {
			s.ARM.ServeHTTP(w, r)
			return
		}
		s.Gateway.ServeHTTP(w, r)
	})
}

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
