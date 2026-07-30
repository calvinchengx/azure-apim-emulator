// Package emulator embeds Azure APIM Emulator in-process for Go tests.
//
//	emu := emulator.StartT(t)
//	response, err := emu.HTTPClient().Get(emu.Origin + "/health")
package emulator

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"

	"github.com/calvinchengx/azure-apim-emulator/internal/auth"
	"github.com/calvinchengx/azure-apim-emulator/internal/config"
	"github.com/calvinchengx/azure-apim-emulator/internal/server"
)

const (
	// DefaultSubscriptionID is used by the pre-seeded APIM service.
	DefaultSubscriptionID = "00000000-0000-0000-0000-000000000000"
	// DefaultResourceGroup is used by the pre-seeded APIM service.
	DefaultResourceGroup = "emulator-rg"
	// DefaultServiceName is the pre-seeded APIM service name.
	DefaultServiceName = "emulator"
)

// Emulator is a running in-process APIM instance.
type Emulator struct {
	Origin             string
	ManagementEndpoint string
	GatewayEndpoint    string
	SubscriptionID     string
	ResourceGroup      string
	ServiceName        string
	DataDir            string
	CACertificate      []byte

	httpServer *httptest.Server
	server     *server.Server
	closeOnce  sync.Once
}

// Options configures Start. The zero-value behavior uses HTTP, permits local
// management requests without a token, and seeds the default service.
type Options struct {
	TLS            bool
	StrictPolicies bool
	DefaultService string
	Location       string
	EntraIssuer    string
	EntraJWKSURL   string
	EntraClient    *http.Client
	BackendClient  *http.Client
}

// Option mutates Options.
type Option func(*Options)

// WithTLS serves the fixture over HTTPS using a certificate trusted by HTTPClient.
func WithTLS() Option { return func(options *Options) { options.TLS = true } }

// WithStrictPolicies rejects unsupported executable policy behavior at upload time.
func WithStrictPolicies() Option {
	return func(options *Options) { options.StrictPolicies = true }
}

// WithService changes the seeded service name and location.
func WithService(name, location string) Option {
	return func(options *Options) {
		options.DefaultService = name
		options.Location = location
	}
}

// WithEntra enables ARM bearer-token validation against an Entra issuer and JWKS endpoint.
func WithEntra(issuer, jwksURL string, client *http.Client) Option {
	return func(options *Options) {
		options.EntraIssuer = issuer
		options.EntraJWKSURL = jwksURL
		options.EntraClient = client
	}
}

// WithBackendClient sets the transport used for gateway backend requests.
func WithBackendClient(client *http.Client) Option {
	return func(options *Options) { options.BackendClient = client }
}

var (
	makeTempDir = os.MkdirTemp
	removeAll   = os.RemoveAll
	newServer   = server.New
)

// Start boots an isolated instance. Call Close to release it.
func Start(opts ...Option) (*Emulator, error) {
	options := Options{DefaultService: DefaultServiceName, Location: "local"}
	for _, apply := range opts {
		apply(&options)
	}
	dataDir, err := makeTempDir("", "azure-apim-emulator-*")
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = removeAll(dataDir)
		}
	}()

	cfg := &config.Config{
		Addr: ":0", DataDir: dataDir, DefaultService: options.DefaultService,
		Location: options.Location, DisableTLS: !options.TLS,
		DisableAuth: options.EntraIssuer == "", StrictPolicies: options.StrictPolicies,
		EntraIssuer: options.EntraIssuer, EntraJWKSURL: options.EntraJWKSURL,
	}
	if err := cfg.Finish(); err != nil {
		return nil, err
	}
	var validator auth.RequestValidator
	core, err := newServer(cfg, validator, options.BackendClient, options.EntraClient)
	if err != nil {
		return nil, err
	}
	var httpServer *httptest.Server
	var caCertificate []byte
	if options.TLS {
		httpServer = httptest.NewTLSServer(core.Handler())
		caCertificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: httpServer.Certificate().Raw})
	} else {
		httpServer = httptest.NewServer(core.Handler())
	}
	failed = false
	return &Emulator{
		Origin: httpServer.URL, ManagementEndpoint: httpServer.URL, GatewayEndpoint: httpServer.URL,
		SubscriptionID: DefaultSubscriptionID, ResourceGroup: DefaultResourceGroup,
		ServiceName: options.DefaultService, DataDir: dataDir,
		CACertificate: caCertificate,
		httpServer:    httpServer, server: core,
	}, nil
}

type tb interface {
	Helper()
	Fatalf(format string, args ...any)
	Cleanup(func())
}

// StartT boots an instance, fails the test on error, and registers cleanup.
func StartT(t tb, opts ...Option) *Emulator {
	t.Helper()
	emu, err := Start(opts...)
	if err != nil {
		t.Fatalf("emulator.StartT: %v", err)
	}
	t.Cleanup(emu.Close)
	return emu
}

// Close stops the instance and removes its isolated data directory.
func (e *Emulator) Close() {
	e.closeOnce.Do(func() {
		if e.httpServer != nil {
			e.httpServer.Close()
		}
		if e.server != nil {
			_ = e.server.Close()
		}
		if e.DataDir != "" {
			_ = removeAll(e.DataDir)
		}
	})
}

// HTTPClient returns a client configured for this instance, including its TLS certificate.
func (e *Emulator) HTTPClient() *http.Client { return e.httpServer.Client() }

// ServiceID returns the ARM ID of the pre-seeded service.
func (e *Emulator) ServiceID() string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ApiManagement/service/%s", e.SubscriptionID, e.ResourceGroup, e.ServiceName)
}
