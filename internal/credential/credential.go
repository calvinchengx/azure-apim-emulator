// Package credential implements APIM's credential manager: obtaining and
// refreshing OAuth2 tokens on behalf of an API, so a backend call can carry a
// credential the caller never sees.
//
// The direction is the thing to keep straight. This is OUTBOUND authentication,
// APIM acting as an OAuth2 CLIENT against a third-party provider. It is not
// authenticating the caller of the API; that is validate-jwt, and it is not the
// developer portal's sign-in, which is identityProviders and
// authorizationServers. The names are close and the resources are unrelated.
package credential

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// GrantType names the OAuth2 grant a stored credential uses.
const (
	// GrantAuthorizationCode needs a human to consent once. APIM keeps the
	// refresh token and renews the access token from then on.
	GrantAuthorizationCode = "authorizationcode"
	// GrantClientCredentials is service-to-service, with no human at any point.
	GrantClientCredentials = "clientcredentials"
)

// maxTokenResponseBytes bounds a token endpoint's reply. A token response is
// small; anything large is a misconfigured endpoint or a hostile one, and
// neither should be read into memory unbounded.
const maxTokenResponseBytes = 1 << 20

// Provider is the OAuth2 endpoint configuration of an authorization provider.
type Provider struct {
	// TokenEndpoint is where codes and refresh tokens are exchanged.
	TokenEndpoint string
	// AuthorizationEndpoint is where a human is sent to consent. Empty for
	// client-credentials providers, which never involve one.
	AuthorizationEndpoint string
	ClientID              string
	ClientSecret          string
	Scopes                string
}

// Token is a credential APIM holds on an API's behalf.
type Token struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresAt    time.Time
	Scopes       string
}

// Expired reports whether a token needs renewing.
//
// The skew is deliberate: a token that expires while a backend call is in
// flight fails the call, and the caller cannot distinguish that from a real
// authorization failure. Renewing slightly early costs one extra token request
// and removes the race.
func (t Token) Expired(now time.Time) bool {
	if t.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(t.ExpiresAt.Add(-30 * time.Second))
}

// Exchanger performs token requests. It is an interface so the gateway can
// supply a client carrying the emulator's own trust settings.
type Exchanger interface {
	Do(*http.Request) (*http.Response, error)
}

// tokenResponse is the RFC 6749 token endpoint reply.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	// ExpiresIn is seconds, and RFC 6749 says it is a number while several real
	// providers send it as a string. json.Number accepts both rather than
	// failing the whole exchange over a quoting difference.
	ExpiresIn json.Number `json:"expires_in"`
	Error     string      `json:"error"`
	ErrorDesc string      `json:"error_description"`
}

// ExchangeCode redeems an authorization code for a token.
func ExchangeCode(ctx context.Context, client Exchanger, provider Provider, code, redirectURI string, now time.Time) (Token, error) {
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}
	return post(ctx, client, provider, form, now)
}

// Refresh renews an access token from a refresh token.
func Refresh(ctx context.Context, client Exchanger, provider Provider, refreshToken string, now time.Time) (Token, error) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	token, err := post(ctx, client, provider, form, now)
	if err != nil {
		return Token{}, err
	}
	if token.RefreshToken == "" {
		// Providers that do not rotate refresh tokens omit it from the reply.
		// Dropping the old one would make the credential single-use, so it is
		// carried forward.
		token.RefreshToken = refreshToken
	}
	return token, nil
}

// ClientCredentials obtains a token with no user involved.
func ClientCredentials(ctx context.Context, client Exchanger, provider Provider, now time.Time) (Token, error) {
	return post(ctx, client, provider, url.Values{"grant_type": {"client_credentials"}}, now)
}

func post(ctx context.Context, client Exchanger, provider Provider, form url.Values, now time.Time) (Token, error) {
	if provider.TokenEndpoint == "" {
		return Token{}, errors.New("credential: provider has no token endpoint")
	}
	form.Set("client_id", provider.ClientID)
	if provider.ClientSecret != "" {
		form.Set("client_secret", provider.ClientSecret)
	}
	// `scope` belongs ONLY to the client-credentials request. RFC 6749 defines
	// no scope parameter for an authorization-code exchange (the scope comes
	// from the code), and on a refresh it may only NARROW, never widen, so
	// sending the configured scopes there can silently change the grant.
	//
	// Sending it anyway is not harmless: a real authorization server issued a
	// token that then failed introspection, which is how this was found. A
	// hand-written fake would have accepted the extra field and the bug would
	// have shipped.
	if provider.Scopes != "" && form.Get("grant_type") == "client_credentials" {
		form.Set("scope", provider.Scopes)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, fmt.Errorf("credential: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return Token{}, fmt.Errorf("credential: token request failed: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxTokenResponseBytes))
	if err != nil {
		return Token{}, fmt.Errorf("credential: cannot read token response: %w", err)
	}
	var parsed tokenResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return Token{}, fmt.Errorf("credential: token response is not JSON: %w", err)
	}
	if parsed.Error != "" {
		// The provider's own error is surfaced, because "invalid_grant" and
		// "invalid_client" mean different things to whoever has to fix the
		// configuration, and collapsing them to "failed" loses that.
		message := parsed.Error
		if parsed.ErrorDesc != "" {
			message += ": " + parsed.ErrorDesc
		}
		return Token{}, fmt.Errorf("credential: provider refused the grant: %s", message)
	}
	if response.StatusCode >= 400 {
		return Token{}, fmt.Errorf("credential: token endpoint returned %d", response.StatusCode)
	}
	if parsed.AccessToken == "" {
		return Token{}, errors.New("credential: token response carried no access_token")
	}
	token := Token{
		AccessToken:  parsed.AccessToken,
		RefreshToken: parsed.RefreshToken,
		TokenType:    parsed.TokenType,
		Scopes:       parsed.Scope,
	}
	if token.TokenType == "" {
		token.TokenType = "Bearer"
	}
	if seconds, err := strconv.ParseInt(parsed.ExpiresIn.String(), 10, 64); err == nil && seconds > 0 {
		token.ExpiresAt = now.Add(time.Duration(seconds) * time.Second)
	}
	return token, nil
}

// LoginLink builds the URL a human visits to consent.
//
// Returned rather than followed: the whole point of the authorization-code
// grant is that a person approves it, and an emulator that auto-approved would
// make a flow look complete that in Azure requires someone to act.
func LoginLink(provider Provider, redirectURI, state string) (string, error) {
	if provider.AuthorizationEndpoint == "" {
		return "", errors.New("credential: provider has no authorization endpoint")
	}
	parsed, err := url.Parse(provider.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("credential: invalid authorization endpoint: %w", err)
	}
	query := parsed.Query()
	query.Set("response_type", "code")
	query.Set("client_id", provider.ClientID)
	query.Set("redirect_uri", redirectURI)
	if provider.Scopes != "" {
		query.Set("scope", provider.Scopes)
		// OIDC says offline_access is IGNORED unless the request also asks for
		// consent, so a provider that follows the spec issues no refresh token
		// without this and the credential works exactly once. Conditional
		// rather than unconditional: forcing re-consent on every login would be
		// its own defect.
		for _, scope := range strings.Fields(provider.Scopes) {
			if strings.EqualFold(scope, "offline_access") {
				query.Set("prompt", "consent")
				break
			}
		}
	}
	if state != "" {
		query.Set("state", state)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}
