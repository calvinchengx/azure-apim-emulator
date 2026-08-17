package gateway

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/calvinchengx/azure-apim-emulator/internal/credential"
	"github.com/calvinchengx/azure-apim-emulator/internal/expression"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

// credentialCache holds live tokens between requests.
//
// It exists because a token obtained per request would make every API call a
// second round trip to the provider, and would burn refresh tokens at a rate
// real providers rate-limit. Keyed by authorization ID, which is what a
// credential IS: one stored grant, shared by every caller permitted to use it.
type credentialCache struct {
	mu     sync.Mutex
	tokens map[string]credential.Token
}

func newCredentialCache() *credentialCache {
	return &credentialCache{tokens: map[string]credential.Token{}}
}

func (c *credentialCache) get(id string) (credential.Token, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	token, ok := c.tokens[id]
	return token, ok
}

func (c *credentialCache) put(id string, token credential.Token) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokens[id] = token
}

// Forget drops a cached token, so a credential deleted or reconnected through
// the management plane is not served from memory afterwards.
func (c *credentialCache) Forget(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.tokens, id)
}

// fetchCredential resolves a stored credential to a usable token.
//
// This is what get-authorization-context calls. It is deliberately the only
// path by which a token leaves the credential store, so the rule that a caller
// never sees the credential has one place to hold rather than several.
func (r *Runtime) fetchCredential(ctx context.Context, st *store.Store, serviceID, providerName, authorizationName string) (expression.AuthorizationContext, error) {
	providerID := serviceID + "/authorizationProviders/" + providerName
	provider, err := st.GetAuthorizationProvider(providerID)
	if err != nil {
		return expression.AuthorizationContext{}, fmt.Errorf("credential: provider %q: %w", providerName, err)
	}
	authorizationID := providerID + "/authorizations/" + authorizationName
	authorization, err := st.GetAuthorization(authorizationID)
	if err != nil {
		return expression.AuthorizationContext{}, fmt.Errorf("credential: authorization %q: %w", authorizationName, err)
	}
	config, err := providerConfig(provider)
	if err != nil {
		return expression.AuthorizationContext{}, err
	}

	now := time.Now()
	if token, ok := r.credentials.get(authorizationID); ok && !token.Expired(now) {
		return authorizationContext(config, token, now), nil
	}

	token, err := r.acquire(ctx, config, authorization, authorizationID, now)
	if err != nil {
		return expression.AuthorizationContext{}, err
	}
	r.credentials.put(authorizationID, token)
	return authorizationContext(config, token, now), nil
}

// acquire obtains a token for a credential, by whichever grant it uses.
func (r *Runtime) acquire(ctx context.Context, config credential.Provider, authorization model.Authorization, authorizationID string, now time.Time) (credential.Token, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	if r.client != nil {
		client = r.client
	}
	if strings.EqualFold(authorization.OAuth2GrantType, credential.GrantClientCredentials) {
		return credential.ClientCredentials(ctx, client, config, now)
	}
	// Authorization code: there is nothing to obtain until a human has
	// consented, so a credential with no refresh token is reported as
	// unconsented rather than as a transport failure. The two need different
	// fixes and an operator should not have to guess which.
	stored, ok := r.credentials.get(authorizationID)
	if !ok || stored.RefreshToken == "" {
		return credential.Token{}, fmt.Errorf(
			"credential: %q has not been consented; call getLoginLinks and confirmConsentCode", authorization.Name)
	}
	return credential.Refresh(ctx, client, config, stored.RefreshToken, now)
}

// providerConfig reads the OAuth2 endpoints and client identity a provider
// carries in its ARM document.
func providerConfig(provider model.AuthorizationProvider) (credential.Provider, error) {
	properties, _ := provider.Document["properties"].(map[string]any)
	oauth, _ := properties["oauth2"].(map[string]any)
	if oauth == nil {
		return credential.Provider{}, fmt.Errorf("credential: provider %q has no oauth2 configuration", provider.Name)
	}
	config := credential.Provider{
		ClientID: stringField(oauth, "clientId"),
		Scopes:   stringField(oauth, "scopes"),
	}
	grants, _ := oauth["grantTypes"].(map[string]any)
	for _, key := range []string{"authorizationCode", "clientCredentials"} {
		grant, _ := grants[key].(map[string]any)
		if grant == nil {
			continue
		}
		if value := stringField(grant, "clientId"); value != "" {
			config.ClientID = value
		}
		if value := stringField(grant, "clientSecret"); value != "" {
			config.ClientSecret = value
		}
		if value := stringField(grant, "scopes"); value != "" {
			config.Scopes = value
		}
	}
	config.TokenEndpoint = stringField(oauth, "tokenEndpoint")
	config.AuthorizationEndpoint = stringField(oauth, "authorizationEndpoint")
	if config.TokenEndpoint == "" {
		return credential.Provider{}, fmt.Errorf("credential: provider %q has no token endpoint", provider.Name)
	}
	return config, nil
}

func stringField(source map[string]any, name string) string {
	value, _ := source[name].(string)
	return value
}

// authorizationContext narrows a token to what a policy may see.
//
// The refresh token is deliberately absent. A policy needs the access token to
// attach the credential; handing it the refresh token would let an expression
// export a long-lived grant, which is the one thing a credential manager exists
// to prevent.
func authorizationContext(config credential.Provider, token credential.Token, now time.Time) expression.AuthorizationContext {
	context := expression.AuthorizationContext{
		AccessToken: token.AccessToken,
		ClientID:    config.ClientID,
		Scopes:      token.Scopes,
	}
	if context.Scopes == "" {
		context.Scopes = config.Scopes
	}
	if !token.ExpiresAt.IsZero() {
		if remaining := int64(token.ExpiresAt.Sub(now).Seconds()); remaining > 0 {
			context.ExpiresIn = remaining
		}
	}
	return context
}

// credentialFetcher binds a request and service to the credential store, so a
// policy names only the provider and authorization while the scope comes from
// where the request actually landed. A policy that could name a service would
// be able to reach another tenant's credentials.
func (r *Runtime) credentialFetcher(req *http.Request, serviceID string) func(string, string) (expression.AuthorizationContext, error) {
	return func(providerName, authorizationName string) (expression.AuthorizationContext, error) {
		st := r.eventStore.Load()
		if st == nil {
			return expression.AuthorizationContext{}, fmt.Errorf("credential: no store is attached")
		}
		return r.fetchCredential(req.Context(), st, serviceID, providerName, authorizationName)
	}
}

// CredentialLoginLink builds the URL a person visits to consent.
func (r *Runtime) CredentialLoginLink(st *store.Store, providerID, authorizationID, redirectURI string) (string, error) {
	provider, err := st.GetAuthorizationProvider(providerID)
	if err != nil {
		return "", err
	}
	config, err := providerConfig(provider)
	if err != nil {
		return "", err
	}
	if redirectURI == "" {
		redirectURI = defaultConsentRedirect
	}
	// The authorization ID is the state, so the code that comes back is bound
	// to the credential it was requested for. Without it a code obtained for
	// one credential could be redeemed into another.
	return credential.LoginLink(config, redirectURI, authorizationID)
}

// CredentialConfirmConsent redeems the code a person came back with.
func (r *Runtime) CredentialConfirmConsent(st *store.Store, providerID, authorizationID, code string) error {
	provider, err := st.GetAuthorizationProvider(providerID)
	if err != nil {
		return err
	}
	config, err := providerConfig(provider)
	if err != nil {
		return err
	}
	token, err := credential.ExchangeCode(context.Background(), r.credentialClient(), config, code, defaultConsentRedirect, time.Now())
	if err != nil {
		return err
	}
	if token.RefreshToken == "" {
		// Without a refresh token the credential works once and then fails at
		// an unpredictable later moment. Refusing now names the cause: the
		// provider was not asked for, or did not grant, offline access.
		return fmt.Errorf("credential: the provider returned no refresh token; request offline access for this client")
	}
	r.credentials.put(authorizationID, token)
	return nil
}

// defaultConsentRedirect is where a provider sends the person after they
// approve. Azure uses its own portal endpoint; the emulator names one so the
// redirect_uri sent at authorize time and at redeem time always match, which
// OAuth2 requires.
const defaultConsentRedirect = "http://localhost/apim-credential-consent"

func (r *Runtime) credentialClient() *http.Client {
	if r.client != nil {
		return r.client
	}
	return &http.Client{Timeout: 30 * time.Second}
}
