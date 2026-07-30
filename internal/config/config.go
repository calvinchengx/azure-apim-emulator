// Package config resolves APIM_* environment variables and command flags.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Config is the resolved process configuration.
type Config struct {
	Addr           string
	DataDir        string
	DefaultService string
	Location       string
	DisableTLS     bool
	DisableAuth    bool
	StrictPolicies bool

	EntraIssuer      string
	EntraJWKSURL     string
	EntraTLSInsecure bool
}

// FromEnvPartial reads configuration without validating it.
func FromEnvPartial() *Config {
	return &Config{
		Addr:             envOr("APIM_ADDR", ":8445"),
		DataDir:          os.Getenv("APIM_DATA_DIR"),
		DefaultService:   envOr("APIM_DEFAULT_SERVICE", "emulator"),
		Location:         envOr("APIM_LOCATION", "local"),
		DisableTLS:       boolEnv("APIM_DISABLE_TLS"),
		DisableAuth:      boolEnv("APIM_DISABLE_AUTH"),
		StrictPolicies:   boolEnv("APIM_STRICT_POLICIES"),
		EntraIssuer:      os.Getenv("APIM_ENTRA_ISSUER"),
		EntraJWKSURL:     os.Getenv("APIM_ENTRA_JWKS_URL"),
		EntraTLSInsecure: boolEnv("APIM_ENTRA_TLS_INSECURE"),
	}
}

// FromEnv returns validated configuration.
func FromEnv() (*Config, error) {
	c := FromEnvPartial()
	return c, c.Finish()
}

// Finish validates and derives dependent fields.
func (c *Config) Finish() error {
	if strings.TrimSpace(c.Addr) == "" {
		return fmt.Errorf("APIM_ADDR must not be empty")
	}
	if strings.TrimSpace(c.DefaultService) == "" {
		return fmt.Errorf("APIM_DEFAULT_SERVICE must not be empty")
	}
	if c.DisableAuth {
		return nil
	}
	if c.EntraIssuer == "" {
		return fmt.Errorf("APIM_ENTRA_ISSUER is required unless APIM_DISABLE_AUTH=true")
	}
	if u, err := url.Parse(c.EntraIssuer); err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("APIM_ENTRA_ISSUER %q is not a URL", c.EntraIssuer)
	}
	base := strings.TrimSuffix(strings.TrimSuffix(c.EntraIssuer, "/"), "/v2.0")
	if c.EntraJWKSURL == "" {
		c.EntraJWKSURL = base + "/discovery/v2.0/keys"
	}
	return nil
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func boolEnv(key string) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
