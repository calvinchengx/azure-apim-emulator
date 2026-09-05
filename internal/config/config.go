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
	// EnforceRBAC turns role assignments into an access decision. Default off:
	// a valid ARM token gets full access, which is what every existing caller
	// and witness assumes. Turning it on is opting IN to being refused.
	EnforceRBAC bool
	// EnforceTiers refuses capabilities the service's SKU does not have.
	// Default off, for the same reason as EnforceRBAC: every existing caller,
	// test and witness builds a Developer service and then creates workspaces,
	// which Azure allows only on Premium. Leaving it off is the emulator being
	// MORE PERMISSIVE than a tenant, which is a real divergence rather than a
	// neutral default, and `docs/parity.md` says so.
	EnforceTiers bool
	// RBACOwner is the principal treated as Owner at subscription scope while
	// enforcement is on.
	//
	// Without it enforcement is unusable: a role assignment is itself an ARM
	// resource whose creation needs a role, so nobody could ever grant the
	// first one. Azure resolves the same circularity with the subscription
	// owner, whose access does not come from an assignment either.
	RBACOwner string

	EntraIssuer string
	// The service's own credentials, used to answer a Key Vault Bearer
	// challenge. This family has no IMDS, so a managed identity is emulated by
	// authenticating to the authority the challenge names.
	IdentityClientID     string
	IdentityClientSecret string
	EntraJWKSURL         string
	EntraTLSInsecure     bool
	// The vault leg. Every emulator in this family serves a self-signed
	// certificate, so talking to a sibling needs the same opt-out entra already
	// has. Backends keep their own per-backend validateCertificateChain.
	KeyVaultTLSInsecure bool
}

// FromEnvPartial reads configuration without validating it.
func FromEnvPartial() *Config {
	return &Config{
		Addr:                 envOr("APIM_ADDR", ":8445"),
		DataDir:              envDefault("APIM_DATA_DIR", DefaultDataDir),
		DefaultService:       envOr("APIM_DEFAULT_SERVICE", "emulator"),
		Location:             envOr("APIM_LOCATION", "local"),
		DisableTLS:           boolEnv("APIM_DISABLE_TLS"),
		DisableAuth:          boolEnv("APIM_DISABLE_AUTH"),
		StrictPolicies:       boolEnv("APIM_STRICT_POLICIES"),
		EnforceRBAC:          boolEnv("APIM_ENFORCE_RBAC"),
		EnforceTiers:         boolEnv("APIM_ENFORCE_TIERS"),
		RBACOwner:            os.Getenv("APIM_RBAC_OWNER"),
		EntraIssuer:          os.Getenv("APIM_ENTRA_ISSUER"),
		IdentityClientID:     os.Getenv("APIM_IDENTITY_CLIENT_ID"),
		IdentityClientSecret: os.Getenv("APIM_IDENTITY_CLIENT_SECRET"),
		EntraJWKSURL:         os.Getenv("APIM_ENTRA_JWKS_URL"),
		EntraTLSInsecure:     boolEnv("APIM_ENTRA_TLS_INSECURE"),
		KeyVaultTLSInsecure:  boolEnv("APIM_KEYVAULT_TLS_INSECURE"),
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
	// Fail fast rather than start an emulator that refuses every request
	// including the one that would fix it.
	if c.EnforceRBAC && strings.TrimSpace(c.RBACOwner) == "" {
		return fmt.Errorf("APIM_RBAC_OWNER is required when APIM_ENFORCE_RBAC=true: with no owner, no role assignment can ever be created")
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

// DefaultDataDir is where state lands when APIM_DATA_DIR is not set at all.
// The family persists by default: an emulator that forgets its services on
// restart is a surprise.
const DefaultDataDir = "./data"

// envDefault distinguishes UNSET from SET-EMPTY, which envOr cannot: unset
// takes the default, while an explicit empty value is honoured as empty. For
// DataDir that is the difference between persisting and running in memory,
// and the compose files use the empty form so a throwaway stack leaves no
// SQLite file in a container layer about to be deleted.
func envDefault(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
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
