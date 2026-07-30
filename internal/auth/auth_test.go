package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testIssuer = "https://issuer.test/tenant/v2.0"

func TestValidatorHappyPaths(t *testing.T) {
	key := mustKey(t)
	jwks := httptest.NewServer(jwksHandler(key, "kid"))
	defer jwks.Close()
	v := New(testIssuer, jwks.URL, false, func() int64 { return 1000 }, jwks.Client())

	token := signToken(t, key, map[string]any{"alg": "RS256", "kid": "kid"}, map[string]any{
		"iss": testIssuer, "aud": "https://management.azure.com/", "exp": 1100, "nbf": 900,
		"oid": "user-id", "appid": "client-id",
	})
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	principal, err := v.ValidateRequest(request)
	if err != nil || principal.ID != "user-id" || principal.Type != "User" {
		t.Fatalf("principal = %+v, %v", principal, err)
	}
	jwks.Close()
	if _, err := v.Validate(token); err != nil {
		t.Fatalf("cached key validation: %v", err)
	}

	appToken := signToken(t, key, map[string]any{"alg": "RS256", "kid": "kid"}, map[string]any{
		"iss": testIssuer, "aud": []string{"other", "https://management.azure.com"}, "appid": "app-id", "sub": "subject", "idtyp": "app",
	})
	principal, err = v.Validate(appToken)
	if err != nil || principal.Type != "ServicePrincipal" || principal.ID != "subject" {
		t.Fatalf("app principal = %+v, %v", principal, err)
	}
}

func TestValidatorTokenFailures(t *testing.T) {
	key := mustKey(t)
	jwks := httptest.NewServer(jwksHandler(key, "kid"))
	defer jwks.Close()
	newValidator := func(now int64) *Validator {
		return New(testIssuer, jwks.URL, false, func() int64 { return now }, jwks.Client())
	}
	validClaims := func() map[string]any {
		return map[string]any{"iss": testIssuer, "aud": "https://management.azure.com", "oid": "user"}
	}
	tests := []struct {
		name  string
		token func() string
		now   int64
	}{
		{"not compact", func() string { return "nope" }, 1000},
		{"bad header encoding", func() string { return "!.!." }, 1000},
		{"bad header json", func() string { return rawToken(t, key, "{", `{}`, "kid") }, 1000},
		{"wrong algorithm", func() string { return signToken(t, key, map[string]any{"alg": "HS256", "kid": "kid"}, validClaims()) }, 1000},
		{"unknown key", func() string {
			return signToken(t, key, map[string]any{"alg": "RS256", "kid": "unknown"}, validClaims())
		}, 1000},
		{"bad signature encoding", func() string {
			token := signToken(t, key, map[string]any{"alg": "RS256", "kid": "kid"}, validClaims())
			return strings.TrimSuffix(token, strings.Split(token, ".")[2]) + "!"
		}, 1000},
		{"bad signature", func() string {
			other := mustKey(t)
			return signToken(t, other, map[string]any{"alg": "RS256", "kid": "kid"}, validClaims())
		}, 1000},
		{"bad payload encoding", func() string {
			return signedParts(t, key, encodeJSON(t, map[string]any{"alg": "RS256", "kid": "kid"}), "!")
		}, 1000},
		{"bad claims json", func() string { return rawToken(t, key, `{"alg":"RS256","kid":"kid"}`, "{", "kid") }, 1000},
		{"wrong issuer", func() string {
			claims := validClaims()
			claims["iss"] = "wrong"
			return signToken(t, key, map[string]any{"alg": "RS256", "kid": "kid"}, claims)
		}, 1000},
		{"wrong audience", func() string {
			claims := validClaims()
			claims["aud"] = "wrong"
			return signToken(t, key, map[string]any{"alg": "RS256", "kid": "kid"}, claims)
		}, 1000},
		{"malformed audience", func() string {
			claims := validClaims()
			claims["aud"] = 42
			return signToken(t, key, map[string]any{"alg": "RS256", "kid": "kid"}, claims)
		}, 1000},
		{"expired", func() string {
			claims := validClaims()
			claims["exp"] = 900
			return signToken(t, key, map[string]any{"alg": "RS256", "kid": "kid"}, claims)
		}, 1000},
		{"not yet valid", func() string {
			claims := validClaims()
			claims["nbf"] = 1100
			return signToken(t, key, map[string]any{"alg": "RS256", "kid": "kid"}, claims)
		}, 1000},
		{"no principal", func() string {
			claims := validClaims()
			delete(claims, "oid")
			return signToken(t, key, map[string]any{"alg": "RS256", "kid": "kid"}, claims)
		}, 1000},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newValidator(test.now).Validate(test.token()); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := newValidator(1000).ValidateRequest(request); !errors.Is(err, ErrNoToken) {
		t.Fatalf("missing token = %v", err)
	}
}

func TestJWKSFailuresAndTLSClient(t *testing.T) {
	key := mustKey(t)
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"status", http.StatusInternalServerError, `{}`},
		{"invalid json", http.StatusOK, `{`},
		{"no rsa", http.StatusOK, `{"keys":[{"kty":"EC","kid":"kid"}]}`},
		{"bad modulus", http.StatusOK, `{"keys":[{"kty":"RSA","kid":"kid","n":"!","e":"AQAB"}]}`},
		{"bad exponent", http.StatusOK, `{"keys":[{"kty":"RSA","kid":"kid","n":"AQ","e":"!"}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			v := New(testIssuer, server.URL, false, func() int64 { return 1 }, server.Client())
			if _, err := v.key("missing"); err == nil {
				t.Fatal("expected key failure")
			}
		})
	}
	closed := httptest.NewServer(jwksHandler(key, "kid"))
	url := closed.URL
	closed.Close()
	if _, err := New(testIssuer, url, false, func() int64 { return 1 }, closed.Client()).key("kid"); err == nil {
		t.Fatal("expected fetch failure")
	}

	tlsServer := httptest.NewTLSServer(jwksHandler(key, "kid"))
	defer tlsServer.Close()
	v := New(testIssuer, tlsServer.URL, true, func() int64 { return 1 }, nil)
	if _, err := v.key("kid"); err != nil {
		t.Fatalf("insecure TLS client: %v", err)
	}
	if _, err := v.key("other"); err == nil {
		t.Fatal("missing kid should fail after refresh")
	}
}

func mustKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func jwksHandler(key *rsa.PrivateKey, kid string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e := big.NewInt(int64(key.PublicKey.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": kid,
			"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(e),
		}}})
	})
}

func signToken(t *testing.T, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	return signedParts(t, key, encodeJSON(t, header), encodeJSON(t, claims))
}

func rawToken(t *testing.T, key *rsa.PrivateKey, header, payload, kid string) string {
	t.Helper()
	_ = kid
	return signedParts(t, key, base64.RawURLEncoding.EncodeToString([]byte(header)), base64.RawURLEncoding.EncodeToString([]byte(payload)))
}

func encodeJSON(t *testing.T, value any) string {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(body)
}

func signedParts(t *testing.T, key *rsa.PrivateKey, header, payload string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(header + "." + payload))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(signature)
}
