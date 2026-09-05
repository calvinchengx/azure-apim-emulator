// Package keyvault retrieves secrets from a Key Vault data-plane endpoint.
package keyvault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const apiVersion = "7.4"

var newHTTPRequest = http.NewRequestWithContext

// Secret is a Key Vault secret payload.
type Secret struct {
	Value       string
	ContentType string
	ID          string
}

// Retriever fetches one secret by its full secret identifier.
type Retriever interface {
	GetSecret(ctx context.Context, secretIdentifier string) (Secret, error)
}

// StatusError is a classified Key Vault data-plane failure.
type StatusError struct {
	Code    string
	Message string
	Status  int
}

func (e *StatusError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// Classify maps a retrieval error onto APIM lastStatus fields.
func Classify(err error) (code, message string) {
	if err == nil {
		return "Success", ""
	}
	var status *StatusError
	if errors.As(err, &status) && status.Code != "" {
		return status.Code, status.Message
	}
	return "Error", err.Error()
}

// HTTP retrieves secrets over the Key Vault REST API.
type HTTP struct {
	Client       *http.Client
	AcquireToken func(context.Context, string, string) (string, error)
	// ClientID and ClientSecret are the service's own credentials, used to
	// answer a vault's Bearer challenge. See acquireClientCredentialsToken for
	// why this exists rather than an IMDS probe.
	ClientID     string
	ClientSecret string
}

// GetSecret GETs a versioned or versionless secret identifier.
func (h HTTP) GetSecret(ctx context.Context, secretIdentifier string) (Secret, error) {
	endpoint, err := secretURL(secretIdentifier)
	if err != nil {
		return Secret{}, err
	}
	secret, challenge, err := h.get(ctx, endpoint, "")
	if err == nil {
		return secret, nil
	}
	if challenge.authorization == "" && challenge.resource == "" {
		return Secret{}, err
	}
	token, tokenErr := h.acquire(ctx, challenge.resource, challenge.authorization)
	if tokenErr != nil {
		return Secret{}, tokenErr
	}
	secret, _, err = h.get(ctx, endpoint, token)
	return secret, err
}

func (h HTTP) get(ctx context.Context, endpoint, token string) (Secret, bearerChallenge, error) {
	client := h.Client
	if client == nil {
		client = http.DefaultClient
	}
	request, err := newHTTPRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Secret{}, bearerChallenge{}, err
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		return Secret{}, bearerChallenge{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return Secret{}, bearerChallenge{}, err
	}
	if response.StatusCode != http.StatusOK {
		challenge := bearerChallenge{}
		if response.StatusCode == http.StatusUnauthorized && token == "" {
			challenge = parseBearerChallenge(response.Header.Get("WWW-Authenticate"))
		}
		return Secret{}, challenge, &StatusError{Code: statusCode(response.StatusCode), Message: errorMessage(response.StatusCode, body), Status: response.StatusCode}
	}
	var document struct {
		Value       string `json:"value"`
		ContentType string `json:"contentType"`
		ID          string `json:"id"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return Secret{}, bearerChallenge{}, err
	}
	if document.Value == "" {
		return Secret{}, bearerChallenge{}, &StatusError{Code: "Error", Message: "Key Vault secret value is missing.", Status: http.StatusOK}
	}
	return Secret{Value: document.Value, ContentType: document.ContentType, ID: document.ID}, bearerChallenge{}, nil
}

type bearerChallenge struct {
	authorization string
	resource      string
}

func (h HTTP) acquire(ctx context.Context, resource, authorization string) (string, error) {
	if h.AcquireToken != nil {
		token, err := h.AcquireToken(ctx, resource, authorization)
		if err != nil {
			return "", &StatusError{Code: "Unauthorized", Message: err.Error(), Status: http.StatusUnauthorized}
		}
		if strings.TrimSpace(token) == "" {
			return "", &StatusError{Code: "Unauthorized", Message: "managed identity token is missing.", Status: http.StatusUnauthorized}
		}
		return token, nil
	}
	if h.ClientID != "" {
		return h.acquireClientCredentialsToken(ctx, resource, authorization)
	}
	return acquireManagedIdentityToken(ctx, h.Client, resource, authorization)
}

// acquireClientCredentialsToken answers the challenge against the authority
// that issued it.
//
// WHY THIS EXISTS RATHER THAN THE IMDS PROBE BELOW. Azure APIM holds a managed
// identity and asks IMDS at 169.254.169.254 for a token. There is no IMDS in
// this family, and `acquireManagedIdentityToken` approximates one by rewriting
// the challenge authority's PATH to /metadata/identity/oauth2/token while
// keeping its host. Pointed at entra-emulator that resolves to the operator
// portal's catch-all, which answers 200 with `<!doctype html>`, and the
// retrieval fails with "invalid character '<'". Measured, against
// azure-keyvault-emulator, which docs/00-charter-and-parity.md names as this
// row's reference.
//
// The challenge already names the authority that issued it and the resource it
// wants a token for, so the honest emulation is to authenticate to THAT
// authority with the service's own credentials. fabric-emulator resolves Key
// Vault secrets the same way (internal/entra MintServicePrincipalToken), and
// for the same reason.
//
// The IMDS path stays for anyone pointing this at a real IMDS; it is used only
// when no credentials are configured.
func (h HTTP) acquireClientCredentialsToken(ctx context.Context, resource, authorization string) (string, error) {
	endpoint, err := clientCredentialsTokenURL(authorization)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {h.ClientID},
		"client_secret": {h.ClientSecret},
		"scope":         {defaultScope(resource)},
	}
	client := h.Client
	if client == nil {
		client = http.DefaultClient
	}
	request, err := newHTTPRequest(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if response.StatusCode != http.StatusOK {
		// Named as the AUTHORITY, not the vault. Reusing the Key Vault message
		// here produced "Key Vault returned HTTP 401" for a refusal by the STS,
		// which sends the reader to the wrong service.
		return "", &StatusError{
			Code:    "Unauthorized",
			Message: fmt.Sprintf("the authority refused the service's credentials (HTTP %d): %s", response.StatusCode, strings.TrimSpace(string(body))),
			Status:  http.StatusUnauthorized,
		}
	}
	var document struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return "", &StatusError{Code: "Unauthorized", Message: "the token endpoint did not return JSON: " + err.Error(), Status: http.StatusUnauthorized}
	}
	if strings.TrimSpace(document.AccessToken) == "" {
		return "", &StatusError{Code: "Unauthorized", Message: "the token endpoint returned no access_token.", Status: http.StatusUnauthorized}
	}
	return document.AccessToken, nil
}

// clientCredentialsTokenURL turns a challenge authority into its token
// endpoint. The authority carries the tenant, so nothing else needs configuring.
func clientCredentialsTokenURL(authorization string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(authorization))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", &StatusError{Code: "Unauthorized", Message: "Key Vault challenge authorization must be an absolute URL.", Status: http.StatusUnauthorized}
	}
	if !strings.Contains(strings.ToLower(parsed.Path), "oauth2/") {
		parsed.Path = strings.TrimRight(parsed.Path, "/") + "/oauth2/v2.0/token"
	}
	return parsed.String(), nil
}

// defaultScope converts the challenge's resource into a v2.0 scope. A vault
// advertises `https://vault.azure.net`; the token endpoint wants
// `https://vault.azure.net/.default`.
func defaultScope(resource string) string {
	trimmed := strings.TrimSpace(resource)
	if trimmed == "" || strings.HasSuffix(trimmed, "/.default") {
		return trimmed
	}
	return strings.TrimRight(trimmed, "/") + "/.default"
}

func acquireManagedIdentityToken(ctx context.Context, client *http.Client, resource, authorization string) (string, error) {
	if client == nil {
		client = http.DefaultClient
	}
	endpoint, err := managedIdentityTokenURL(authorization, resource)
	if err != nil {
		return "", err
	}
	request, err := newHTTPRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Metadata", "true")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if response.StatusCode != http.StatusOK {
		return "", &StatusError{Code: statusCode(response.StatusCode), Message: errorMessage(response.StatusCode, body), Status: response.StatusCode}
	}
	var document struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return "", err
	}
	if strings.TrimSpace(document.AccessToken) == "" {
		return "", &StatusError{Code: "Unauthorized", Message: "managed identity token is missing.", Status: http.StatusUnauthorized}
	}
	return document.AccessToken, nil
}

func managedIdentityTokenURL(authorization, resource string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(authorization))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", &StatusError{Code: "Unauthorized", Message: "Key Vault challenge authorization must be an absolute URL.", Status: http.StatusUnauthorized}
	}
	if !strings.Contains(strings.ToLower(parsed.Path), "oauth2/token") {
		parsed.Path = "/metadata/identity/oauth2/token"
	}
	query := parsed.Query()
	if query.Get("api-version") == "" {
		query.Set("api-version", "2018-02-01")
	}
	if resource != "" && query.Get("resource") == "" {
		query.Set("resource", resource)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func parseBearerChallenge(header string) bearerChallenge {
	trimmed := strings.TrimSpace(header)
	if trimmed == "" || !strings.HasPrefix(strings.ToLower(trimmed), "bearer") {
		return bearerChallenge{}
	}
	rest := strings.TrimSpace(trimmed[len("bearer"):])
	result := bearerChallenge{}
	for _, part := range splitChallenge(rest) {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch key {
		case "authorization", "authorization_uri":
			result.authorization = value
		case "resource", "resource_id":
			result.resource = value
		}
	}
	return result
}

func splitChallenge(header string) []string {
	var parts []string
	var current strings.Builder
	quoted := false
	for _, r := range header {
		switch {
		case r == '"':
			quoted = !quoted
			current.WriteRune(r)
		case r == ',' && !quoted:
			if part := strings.TrimSpace(current.String()); part != "" {
				parts = append(parts, part)
			}
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	if part := strings.TrimSpace(current.String()); part != "" {
		parts = append(parts, part)
	}
	return parts
}

func secretURL(secretIdentifier string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(secretIdentifier))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", &StatusError{Code: "Error", Message: "secretIdentifier must be an absolute Key Vault secret URL.", Status: http.StatusBadRequest}
	}
	trimmed := strings.Trim(parsed.Path, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 || parts[0] != "secrets" || parts[1] == "" {
		return "", &StatusError{Code: "Error", Message: "secretIdentifier must reference /secrets/{name}.", Status: http.StatusBadRequest}
	}
	query := parsed.Query()
	if query.Get("api-version") == "" {
		query.Set("api-version", apiVersion)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func statusCode(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "Unauthorized"
	case http.StatusForbidden:
		return "Forbidden"
	case http.StatusNotFound:
		return "NotFound"
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return "Timeout"
	default:
		return "Error"
	}
}

func errorMessage(status int, body []byte) string {
	var document struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &document) == nil && document.Error.Message != "" {
		if document.Error.Code != "" {
			return document.Error.Code + ": " + document.Error.Message
		}
		return document.Error.Message
	}
	return fmt.Sprintf("Key Vault returned HTTP %d.", status)
}
