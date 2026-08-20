package gateway

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
)

// The intervals Microsoft documents for <openid-config>: "Configuration
// including the JSON Web Key Set (JWKS) is pulled from the endpoint every 1
// hour and cached. If the token being validated references a validation key
// (using `kid` claim) that is missing in cached configuration, or if retrieval
// fails, API Management pulls from the endpoint at most once per 5 min."
//
// The reference adds that they "are subject to change without notice", so the
// SHAPE is what is being reproduced here, not the exact numbers: cache, refresh
// on a kid that is not held, and rate-limit that refresh so an unknown kid
// cannot be used to hammer the provider.
const (
	openIDConfigTTL   = time.Hour
	openIDRetryPeriod = 5 * time.Minute
)

type openIDEntry struct {
	issuer      string
	keys        map[string]*rsa.PublicKey
	fetchedAt   time.Time
	lastAttempt time.Time
}

// validateTokenAgainst verifies a token against the signing keys published by
// the given discovery endpoints, returning the issuer of the endpoint whose key
// verified it.
//
// Only that endpoint's issuer is returned, not every configured one: a token
// signed by one provider must not inherit another provider's issuer, which is
// what makes the issuer check worth doing when a policy names several.
func (r *Runtime) validateTokenAgainst(token string, configs []policy.OpenIDConfig) ([]string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("openid-config: compact JWS required")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("openid-config: header encoding")
	}
	var header struct{ Alg, Kid string }
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Alg != "RS256" {
		return nil, fmt.Errorf("openid-config: unsupported header")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("openid-config: signature encoding")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))

	lastErr := fmt.Errorf("openid-config: no endpoint held a usable key")
	for _, config := range configs {
		key, issuer, err := r.openIDKey(config, header.Kid)
		if err != nil {
			lastErr = err
			continue
		}
		if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) == nil {
			return []string{issuer}, nil
		}
		lastErr = fmt.Errorf("openid-config: signature did not verify against %s", config.URL)
	}
	return nil, lastErr
}

// openIDKey returns the signing key for a kid, fetching or refreshing the
// endpoint's configuration when the cache cannot answer.
func (r *Runtime) openIDKey(config policy.OpenIDConfig, kid string) (*rsa.PublicKey, string, error) {
	now := time.Now()
	r.openIDMu.Lock()
	defer r.openIDMu.Unlock()
	if r.openIDConfigs == nil {
		r.openIDConfigs = map[string]*openIDEntry{}
	}
	entry := r.openIDConfigs[config.URL]
	stale := entry == nil || now.Sub(entry.fetchedAt) >= openIDConfigTTL
	// A kid the cached configuration does not hold is the rotation case: refetch,
	// but no more often than the retry period, so an unknown kid cannot be used
	// to drive requests at the provider.
	missing := entry != nil && kid != "" && entry.keys[kid] == nil
	if (stale || missing) && (entry == nil || now.Sub(entry.lastAttempt) >= openIDRetryPeriod || stale) {
		fetched, err := r.fetchOpenIDConfig(config.URL)
		if entry == nil {
			entry = &openIDEntry{}
			r.openIDConfigs[config.URL] = entry
		}
		entry.lastAttempt = now
		if err == nil {
			entry.issuer, entry.keys, entry.fetchedAt = fetched.issuer, fetched.keys, now
		} else if entry.keys == nil {
			// Nothing cached to fall back on. validate-connectivity only governs
			// whether an unreachable endpoint is a CONFIGURATION error; it cannot
			// conjure keys, so a token still fails either way.
			return nil, "", fmt.Errorf("openid-config: %s: %w", config.URL, err)
		}
	}
	if entry == nil || entry.keys[kid] == nil {
		return nil, "", fmt.Errorf("openid-config: %s holds no key %q", config.URL, kid)
	}
	return entry.keys[kid], entry.issuer, nil
}

func (r *Runtime) fetchOpenIDConfig(url string) (openIDEntry, error) {
	document, err := r.getJSON(url)
	if err != nil {
		return openIDEntry{}, err
	}
	var metadata struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(document, &metadata); err != nil {
		return openIDEntry{}, fmt.Errorf("parse configuration: %w", err)
	}
	// Both are required by OpenID Connect Discovery, and the reference points at
	// that spec, so a document missing either is not "a compliant OpenID
	// configuration endpoint".
	if metadata.Issuer == "" || metadata.JWKSURI == "" {
		return openIDEntry{}, fmt.Errorf("configuration lacks issuer or jwks_uri")
	}
	raw, err := r.getJSON(metadata.JWKSURI)
	if err != nil {
		return openIDEntry{}, err
	}
	var jwks struct {
		Keys []struct{ Kty, Kid, N, E string } `json:"keys"`
	}
	if err := json.Unmarshal(raw, &jwks); err != nil {
		return openIDEntry{}, fmt.Errorf("parse JWKS: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, item := range jwks.Keys {
		if item.Kty != "RSA" {
			continue
		}
		n, errN := base64.RawURLEncoding.DecodeString(item.N)
		e, errE := base64.RawURLEncoding.DecodeString(item.E)
		if errN != nil || errE != nil {
			continue
		}
		keys[item.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	if len(keys) == 0 {
		return openIDEntry{}, fmt.Errorf("JWKS contained no RSA keys")
	}
	return openIDEntry{issuer: metadata.Issuer, keys: keys}, nil
}

func (r *Runtime) getJSON(url string) ([]byte, error) {
	response, err := r.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %d", url, response.StatusCode)
	}
	return io.ReadAll(io.LimitReader(response.Body, 1<<20))
}
