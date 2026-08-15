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
	Client *http.Client
}

// GetSecret GETs a versioned or versionless secret identifier.
func (h HTTP) GetSecret(ctx context.Context, secretIdentifier string) (Secret, error) {
	endpoint, err := secretURL(secretIdentifier)
	if err != nil {
		return Secret{}, err
	}
	client := h.Client
	if client == nil {
		client = http.DefaultClient
	}
	request, err := newHTTPRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Secret{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return Secret{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return Secret{}, err
	}
	if response.StatusCode != http.StatusOK {
		return Secret{}, &StatusError{Code: statusCode(response.StatusCode), Message: errorMessage(response.StatusCode, body), Status: response.StatusCode}
	}
	var document struct {
		Value       string `json:"value"`
		ContentType string `json:"contentType"`
		ID          string `json:"id"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return Secret{}, err
	}
	if document.Value == "" {
		return Secret{}, &StatusError{Code: "Error", Message: "Key Vault secret value is missing.", Status: http.StatusOK}
	}
	return Secret{Value: document.Value, ContentType: document.ContentType, ID: document.ID}, nil
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
