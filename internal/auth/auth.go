// Package auth validates ARM bearer tokens against an Entra issuer and JWKS.
package auth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
)

var (
	// ErrNoToken is returned when the request carries no bearer token.
	ErrNoToken = errors.New("missing bearer token")
	// ErrBadToken is returned when token validation fails.
	ErrBadToken = errors.New("invalid bearer token")
)

// Principal is a validated ARM caller.
type Principal struct {
	ID    string
	AppID string
	Type  string
}

// RequestValidator validates management requests.
type RequestValidator interface {
	ValidateRequest(*http.Request) (*Principal, error)
}

// AllowAll is used only when explicitly configured or injected by tests.
type AllowAll struct{}

// ValidateRequest returns a deterministic local principal.
func (AllowAll) ValidateRequest(*http.Request) (*Principal, error) {
	return &Principal{ID: "local-administrator", Type: "User"}, nil
}

// Validator verifies RS256 tokens against a JWKS.
type Validator struct {
	Issuer string
	Now    func() int64

	jwksURL string
	client  *http.Client
	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey
}

// New constructs an ARM-token validator.
func New(issuer, jwksURL string, insecure bool, now func() int64, client *http.Client) *Validator {
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		if insecure {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		client = &http.Client{Transport: transport}
	}
	return &Validator{Issuer: issuer, Now: now, jwksURL: jwksURL, client: client, keys: map[string]*rsa.PublicKey{}}
}

// ValidateRequest extracts and validates a Bearer token.
func (v *Validator) ValidateRequest(r *http.Request) (*Principal, error) {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return nil, ErrNoToken
	}
	return v.Validate(strings.TrimSpace(header[len(prefix):]))
}

// Validate verifies signature and ARM claims.
func (v *Validator) Validate(token string) (*Principal, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: compact JWS required", ErrBadToken)
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header encoding", ErrBadToken)
	}
	var header struct{ Alg, Kid string }
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Alg != "RS256" || header.Kid == "" {
		return nil, fmt.Errorf("%w: unsupported header", ErrBadToken)
	}
	key, err := v.key(header.Kid)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadToken, err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature encoding", ErrBadToken)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return nil, fmt.Errorf("%w: signature", ErrBadToken)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload encoding", ErrBadToken)
	}
	var claims struct {
		Issuer    string          `json:"iss"`
		Audience  json.RawMessage `json:"aud"`
		Expires   int64           `json:"exp"`
		NotBefore int64           `json:"nbf"`
		ObjectID  string          `json:"oid"`
		Subject   string          `json:"sub"`
		AppID     string          `json:"appid"`
		IDType    string          `json:"idtyp"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("%w: claims", ErrBadToken)
	}
	if claims.Issuer != v.Issuer {
		return nil, fmt.Errorf("%w: issuer", ErrBadToken)
	}
	if !armAudience(claims.Audience) {
		return nil, fmt.Errorf("%w: audience", ErrBadToken)
	}
	now := v.Now()
	const skew = int64(60)
	if claims.Expires != 0 && now > claims.Expires+skew {
		return nil, fmt.Errorf("%w: expired", ErrBadToken)
	}
	if claims.NotBefore != 0 && now < claims.NotBefore-skew {
		return nil, fmt.Errorf("%w: not yet valid", ErrBadToken)
	}
	principal := &Principal{ID: claims.ObjectID, AppID: claims.AppID, Type: "User"}
	if principal.ID == "" {
		principal.ID = claims.Subject
	}
	if claims.IDType == "app" || (claims.ObjectID == "" && claims.AppID != "") {
		principal.Type = "ServicePrincipal"
	}
	if principal.ID == "" {
		return nil, fmt.Errorf("%w: principal", ErrBadToken)
	}
	return principal, nil
}

func armAudience(raw json.RawMessage) bool {
	accepted := map[string]bool{"https://management.azure.com": true, "https://management.azure.com/": true}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return accepted[one]
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, value := range many {
			if accepted[value] {
				return true
			}
		}
	}
	return false
}

func (v *Validator) key(kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key := v.keys[kid]
	v.mu.RUnlock()
	if key != nil {
		return key, nil
	}
	if err := v.refresh(); err != nil {
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if key = v.keys[kid]; key != nil {
		return key, nil
	}
	return nil, fmt.Errorf("key %q not found", kid)
}

func (v *Validator) refresh() error {
	response, err := v.client.Get(v.jwksURL)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch JWKS: status %d", response.StatusCode)
	}
	var document struct {
		Keys []struct{ Kty, Kid, N, E string } `json:"keys"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		return fmt.Errorf("parse JWKS: %w", err)
	}
	fresh := map[string]*rsa.PublicKey{}
	for _, item := range document.Keys {
		if item.Kty != "RSA" {
			continue
		}
		n, errN := base64.RawURLEncoding.DecodeString(item.N)
		e, errE := base64.RawURLEncoding.DecodeString(item.E)
		if errN != nil || errE != nil {
			continue
		}
		fresh[item.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	if len(fresh) == 0 {
		return errors.New("JWKS contained no RSA keys")
	}
	v.mu.Lock()
	v.keys = fresh
	v.mu.Unlock()
	return nil
}
