package config

import (
	"strings"
	"testing"
)

func TestFromEnvAndFinish(t *testing.T) {
	t.Setenv("APIM_ADDR", ":9000")
	t.Setenv("APIM_DATA_DIR", "/tmp/apim-test")
	t.Setenv("APIM_DEFAULT_SERVICE", "testing")
	t.Setenv("APIM_LOCATION", "test-location")
	t.Setenv("APIM_DISABLE_TLS", "yes")
	t.Setenv("APIM_DISABLE_AUTH", "true")
	t.Setenv("APIM_STRICT_POLICIES", "1")
	cfg, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != ":9000" || cfg.DataDir != "/tmp/apim-test" || cfg.DefaultService != "testing" ||
		!cfg.DisableTLS || !cfg.DisableAuth || !cfg.StrictPolicies {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{"empty addr", Config{DefaultService: "x", DisableAuth: true}, "APIM_ADDR"},
		{"empty service", Config{Addr: ":1", DisableAuth: true}, "APIM_DEFAULT_SERVICE"},
		{"issuer required", Config{Addr: ":1", DefaultService: "x"}, "APIM_ENTRA_ISSUER"},
		{"bad issuer", Config{Addr: ":1", DefaultService: "x", EntraIssuer: "not-a-url"}, "not a URL"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.cfg.Finish(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Finish() = %v", err)
			}
		})
	}
	cfg := Config{Addr: ":1", DefaultService: "x", EntraIssuer: "https://issuer.test/tenant/v2.0"}
	if err := cfg.Finish(); err != nil {
		t.Fatal(err)
	}
	if cfg.EntraJWKSURL != "https://issuer.test/tenant/discovery/v2.0/keys" {
		t.Fatalf("JWKS = %q", cfg.EntraJWKSURL)
	}
	cfg.EntraJWKSURL = "https://keys.test/jwks"
	if err := cfg.Finish(); err != nil || cfg.EntraJWKSURL != "https://keys.test/jwks" {
		t.Fatalf("explicit JWKS: %+v, %v", cfg, err)
	}
}

func TestEnvHelpers(t *testing.T) {
	t.Setenv("PRESENT", "value")
	t.Setenv("BOOL", "ON")
	if envOr("PRESENT", "fallback") != "value" || envOr("ABSENT", "fallback") != "fallback" {
		t.Fatal("envOr mismatch")
	}
	if !boolEnv("BOOL") || boolEnv("ABSENT") {
		t.Fatal("boolEnv mismatch")
	}
}

// Enforcement with no owner would refuse every request including the one that
// grants the first role, so it is a startup error rather than a silent trap.
func TestEnforceRBACRequiresAnOwner(t *testing.T) {
	cfg := &Config{Addr: ":0", DefaultService: "emulator", DisableAuth: true, EnforceRBAC: true}
	if err := cfg.Finish(); err == nil {
		t.Fatal("APIM_ENFORCE_RBAC without APIM_RBAC_OWNER must fail fast")
	}
	cfg.RBACOwner = "root"
	if err := cfg.Finish(); err != nil {
		t.Fatalf("a named owner must satisfy it: %v", err)
	}
}
