package gateway

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
)

// signedToken mints an RS256 JWT naming the key it used, the way a provider does.
func signedToken(t *testing.T, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"alg":"RS256","kid":%q}`, kid)))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"witness"}`))
	digest := sha256.Sum256([]byte(header + "." + payload))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func jwkOf(key *rsa.PrivateKey, kid string) map[string]string {
	return map[string]string{
		"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

// TestOpenIDConfigSelectsTheKeyByKid pins the behaviour a single-key JWKS cannot
// test: with several keys published, the token validates only if the one its
// `kid` names is the one used.
func TestOpenIDConfigSelectsTheKeyByKid(t *testing.T) {
	first, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	second, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	var discoveryHits, jwksHits int
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		discoveryHits++
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": server.URL, "jwks_uri": server.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		jwksHits++
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{jwkOf(first, "one"), jwkOf(second, "two")}})
	})

	runtime := New("fallback", server.Client())
	configs := []policy.OpenIDConfig{{URL: server.URL + "/.well-known/openid-configuration", ValidateConnectivity: true}}

	// Each published key validates the token that names it.
	for _, testCase := range []struct {
		kid string
		key *rsa.PrivateKey
	}{{"one", first}, {"two", second}} {
		issuers, err := runtime.validateTokenAgainst(signedToken(t, testCase.key, testCase.kid), configs)
		if err != nil {
			t.Fatalf("kid %q: %v", testCase.kid, err)
		}
		if len(issuers) != 1 || issuers[0] != server.URL {
			t.Fatalf("kid %q gave issuers %v, want the endpoint's own", testCase.kid, issuers)
		}
	}

	// A token naming one key but signed by the other must not validate. This is
	// the case a single-key JWKS could never catch.
	if _, err := runtime.validateTokenAgainst(signedToken(t, second, "one"), configs); err == nil {
		t.Fatal("a token signed by a different key than its kid names was accepted")
	}
	// A key the endpoint does not publish at all.
	if _, err := runtime.validateTokenAgainst(signedToken(t, stranger, "one"), configs); err == nil {
		t.Fatal("a token signed by an unpublished key was accepted")
	}
	// An unknown kid.
	if _, err := runtime.validateTokenAgainst(signedToken(t, first, "three"), configs); err == nil {
		t.Fatal("a token naming a kid the endpoint does not publish was accepted")
	}

	// The configuration is cached: the first call fetched it, and the rest did
	// not refetch, because every kid asked for after that was already held.
	if discoveryHits < 1 || jwksHits < 1 {
		t.Fatalf("endpoint was never consulted: discovery=%d jwks=%d", discoveryHits, jwksHits)
	}
	if discoveryHits > 2 {
		t.Fatalf("configuration refetched %d times for keys it already held", discoveryHits)
	}

	// Malformed input is refused rather than panicking.
	for _, bad := range []string{"", "not-a-jwt", "a.b", "!!!.x.y"} {
		if _, err := runtime.validateTokenAgainst(bad, configs); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	// An endpoint that answers nothing usable.
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer broken.Close()
	if _, err := runtime.validateTokenAgainst(signedToken(t, first, "one"), []policy.OpenIDConfig{{URL: broken.URL}}); err == nil {
		t.Fatal("an unreachable configuration endpoint was treated as valid")
	}
}

// TestOpenIDConfigRefusesUnusableEndpoints covers what the fetcher must reject:
// a document that is not a compliant OpenID configuration, and a JWKS that
// carries nothing it can use.
func TestOpenIDConfigRefusesUnusableEndpoints(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	token := signedToken(t, key, "one")

	serve := func(discovery, jwks string) string {
		mux := http.NewServeMux()
		server := httptest.NewServer(mux)
		t.Cleanup(server.Close)
		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
			if discovery == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(strings.ReplaceAll(discovery, "SELF", server.URL)))
		})
		mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(jwks))
		})
		return server.URL
	}

	for _, testCase := range []struct {
		name      string
		discovery string
		jwks      string
	}{
		{"discovery is not JSON", `{not json`, `{"keys":[]}`},
		{"no issuer", `{"jwks_uri":"SELF/jwks"}`, `{"keys":[]}`},
		{"no jwks_uri", `{"issuer":"SELF"}`, `{"keys":[]}`},
		{"discovery missing", ``, `{"keys":[]}`},
		{"JWKS is not JSON", `{"issuer":"SELF","jwks_uri":"SELF/jwks"}`, `{not json`},
		{"JWKS has no RSA keys", `{"issuer":"SELF","jwks_uri":"SELF/jwks"}`, `{"keys":[{"kty":"EC","kid":"one"}]}`},
		{"JWKS key is not decodable", `{"issuer":"SELF","jwks_uri":"SELF/jwks"}`, `{"keys":[{"kty":"RSA","kid":"one","n":"!!!","e":"AQAB"}]}`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			url := serve(testCase.discovery, testCase.jwks)
			runtime := New("fallback", http.DefaultClient)
			if _, err := runtime.validateTokenAgainst(token, []policy.OpenIDConfig{{URL: url + "/.well-known/openid-configuration"}}); err == nil {
				t.Fatalf("accepted a token against an endpoint where %s", testCase.name)
			}
		})
	}

	// Discovery answers, but the jwks_uri it names does not.
	deadJWKS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"https://issuer.test","jwks_uri":"http://127.0.0.1:1/jwks"}`))
	}))
	defer deadJWKS.Close()
	if _, err := New("fallback", http.DefaultClient).validateTokenAgainst(token, []policy.OpenIDConfig{{URL: deadJWKS.URL}}); err == nil {
		t.Fatal("accepted a token when the jwks_uri could not be reached")
	}

	// A url that does not resolve at all.
	runtime := New("fallback", http.DefaultClient)
	if _, err := runtime.validateTokenAgainst(token, []policy.OpenIDConfig{{URL: "http://127.0.0.1:1/nowhere"}}); err == nil {
		t.Fatal("accepted a token against an unreachable endpoint")
	}
	// No endpoints named at all.
	if _, err := runtime.validateTokenAgainst(token, nil); err == nil {
		t.Fatal("accepted a token with no configuration endpoint")
	}
	// A header that is not RS256.
	notRS256 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"one"}`)) + ".e30.c2ln"
	if _, err := runtime.validateTokenAgainst(notRS256, []policy.OpenIDConfig{{URL: "http://127.0.0.1:1/nowhere"}}); err == nil {
		t.Fatal("accepted a token that was not RS256")
	}
	// A signature that is not base64url.
	badSignature := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"one"}`)) + ".e30.!!!"
	if _, err := runtime.validateTokenAgainst(badSignature, []policy.OpenIDConfig{{URL: "http://127.0.0.1:1/nowhere"}}); err == nil {
		t.Fatal("accepted a token whose signature was not base64url")
	}
	// A header that is not base64url.
	if _, err := runtime.validateTokenAgainst("!!!.e30.c2ln", []policy.OpenIDConfig{{URL: "http://127.0.0.1:1/nowhere"}}); err == nil {
		t.Fatal("accepted a token whose header was not base64url")
	}
}
