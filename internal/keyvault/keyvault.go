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
	return acquireManagedIdentityToken(ctx, h.Client, resource, authorization)
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
