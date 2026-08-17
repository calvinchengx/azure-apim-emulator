package arm

import (
	"errors"
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

// Credential manager: authorizationProviders, the credentials stored under
// them, and the access policies naming who may use each credential.
//
// Not to be confused with authorizationServers, which this handler also serves
// and which is a different resource entirely: that is the OAuth2 server the
// developer portal console sends users to. These are the credentials APIM uses
// when calling a BACKEND.

func (h *Handler) authorizationProviderCollection(w http.ResponseWriter, r *http.Request, serviceID string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	values, err := h.Store.ListAuthorizationProviders(serviceID)
	if err != nil {
		h.storeError(w, err, serviceID)
		return
	}
	resources := make([]map[string]any, 0, len(values))
	for _, value := range values {
		resources = append(resources, authorizationProviderWire(value))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
}

func (h *Handler) authorizationProviderResource(w http.ResponseWriter, r *http.Request, value model.AuthorizationProvider) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetAuthorizationProvider(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		writeResource(w, http.StatusOK, authorizationProviderWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetAuthorizationProvider(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, value.ID())
				return
			}
			value = existing
		}
		var body struct {
			Properties struct {
				DisplayName      *string `json:"displayName"`
				IdentityProvider *string `json:"identityProvider"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if body.Properties.DisplayName != nil {
			value.DisplayName = *body.Properties.DisplayName
		}
		if body.Properties.IdentityProvider != nil {
			value.IdentityProvider = *body.Properties.IdentityProvider
		}
		if value.IdentityProvider == "" {
			writeError(w, http.StatusBadRequest, "ValidationError",
				"properties.identityProvider is required (for example \"aad\", \"github\", or \"oauth2\").", "properties.identityProvider")
			return
		}
		value.Document = document
		cleanResourceDocument(value.Document)
		got, err := h.Store.UpsertAuthorizationProvider(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, authorizationProviderWire(got), got.ETag)
	case http.MethodDelete:
		// Cascades to every credential under the provider. Withdrawing an
		// integration must revoke what it issued, not orphan it.
		if err := h.Store.DeleteAuthorizationProvider(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) authorizationCollection(w http.ResponseWriter, r *http.Request, providerID string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	values, err := h.Store.ListAuthorizations(providerID)
	if err != nil {
		h.storeError(w, err, providerID)
		return
	}
	resources := make([]map[string]any, 0, len(values))
	for _, value := range values {
		resources = append(resources, authorizationWire(value))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
}

func (h *Handler) authorizationResource(w http.ResponseWriter, r *http.Request, value model.Authorization) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetAuthorization(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		writeResource(w, http.StatusOK, authorizationWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetAuthorization(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, value.ID())
				return
			}
			value = existing
		}
		var body struct {
			Properties struct {
				AuthorizationType *string `json:"authorizationType"`
				OAuth2GrantType   *string `json:"oauth2grantType"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if body.Properties.AuthorizationType != nil {
			value.AuthorizationType = *body.Properties.AuthorizationType
		}
		if body.Properties.OAuth2GrantType != nil {
			value.OAuth2GrantType = *body.Properties.OAuth2GrantType
		}
		if !validGrantType(value.OAuth2GrantType) {
			writeError(w, http.StatusBadRequest, "ValidationError",
				"properties.oauth2grantType must be \"AuthorizationCode\" or \"ClientCredentials\".", "properties.oauth2grantType")
			return
		}
		if errors.Is(existingErr, store.ErrNotFound) {
			// A new authorization-code credential is NOT usable yet: a human
			// has to consent. Reporting it as Connected on creation would make
			// the emulator claim a credential exists that in Azure does not.
			value.Status = "Error"
			value.ErrorMsg = "The credential has not been consented. Call getLoginLinks and confirmConsentCode."
			if strings.EqualFold(value.OAuth2GrantType, "clientcredentials") {
				// Client credentials need no human, so the credential is usable
				// as soon as it is configured.
				value.Status, value.ErrorMsg = "Connected", ""
			}
		}
		value.Document = document
		cleanResourceDocument(value.Document)
		got, err := h.Store.UpsertAuthorization(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, authorizationWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteAuthorization(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func validGrantType(value string) bool {
	return strings.EqualFold(value, "authorizationcode") || strings.EqualFold(value, "clientcredentials")
}

func (h *Handler) accessPolicyCollection(w http.ResponseWriter, r *http.Request, authorizationID string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	values, err := h.Store.ListAuthorizationAccessPolicies(authorizationID)
	if err != nil {
		h.storeError(w, err, authorizationID)
		return
	}
	resources := make([]map[string]any, 0, len(values))
	for _, value := range values {
		resources = append(resources, accessPolicyWire(value))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
}

func (h *Handler) accessPolicyResource(w http.ResponseWriter, r *http.Request, value model.AuthorizationAccessPolicy) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetAuthorizationAccessPolicy(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		writeResource(w, http.StatusOK, accessPolicyWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetAuthorizationAccessPolicy(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, value.ID())
				return
			}
			value = existing
		}
		var body struct {
			Properties struct {
				TenantID *string `json:"tenantId"`
				ObjectID *string `json:"objectId"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if body.Properties.TenantID != nil {
			value.TenantID = *body.Properties.TenantID
		}
		if body.Properties.ObjectID != nil {
			value.ObjectID = *body.Properties.ObjectID
		}
		if value.ObjectID == "" {
			writeError(w, http.StatusBadRequest, "ValidationError",
				"properties.objectId is required: an access policy names the principal permitted to use the credential.", "properties.objectId")
			return
		}
		value.Document = document
		cleanResourceDocument(value.Document)
		got, err := h.Store.UpsertAuthorizationAccessPolicy(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, accessPolicyWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteAuthorizationAccessPolicy(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func authorizationProviderWire(v model.AuthorizationProvider) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/authorizationProviders"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["displayName"], properties["identityProvider"] = v.DisplayName, v.IdentityProvider
	// The client secret is never echoed. A GET that returned it would turn the
	// management plane into a way to read back a secret that was write-only in
	// Azure, which is the opposite of what a credential manager is for.
	if oauth, ok := properties["oauth2"].(map[string]any); ok {
		if grants, ok := oauth["grantTypes"].(map[string]any); ok {
			redactGrantSecrets(grants)
		}
	}
	return result
}

// redactGrantSecrets strips client secrets from a provider's grant config.
func redactGrantSecrets(grants map[string]any) {
	for _, value := range grants {
		grant, ok := value.(map[string]any)
		if !ok {
			continue
		}
		delete(grant, "clientSecret")
	}
}

func authorizationWire(v model.Authorization) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/authorizationProviders/authorizations"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["authorizationType"] = v.AuthorizationType
	properties["oauth2grantType"] = v.OAuth2GrantType
	properties["status"] = v.Status
	if v.ErrorMsg != "" {
		properties["error"] = map[string]any{"code": "Unauthenticated", "message": v.ErrorMsg}
	} else {
		delete(properties, "error")
	}
	// The stored tokens never appear on the wire. That is the whole property a
	// credential manager sells: the caller gets the effect of the credential,
	// never the credential.
	delete(properties, "accessToken")
	delete(properties, "refreshToken")
	return result
}

func accessPolicyWire(v model.AuthorizationAccessPolicy) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/authorizationProviders/authorizations/accessPolicies"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["tenantId"], properties["objectId"] = v.TenantID, v.ObjectID
	return result
}

// authorizationAction serves the two POST operations that carry out consent.
//
// These exist because the authorization-code grant needs a human, and ARM is
// how Azure brokers that: getLoginLinks hands back a URL for a person to visit,
// and confirmConsentCode redeems what they came back with. The emulator does
// NOT auto-consent, because a flow that completes without anyone approving it
// would look finished here and stall in Azure.
func (h *Handler) authorizationAction(w http.ResponseWriter, r *http.Request, value model.Authorization, action string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	authorization, err := h.Store.GetAuthorization(value.ID())
	if err != nil {
		h.storeError(w, err, value.ID())
		return
	}
	if !strings.EqualFold(authorization.OAuth2GrantType, "authorizationcode") {
		writeError(w, http.StatusBadRequest, "ValidationError",
			"Consent applies to the authorizationCode grant only; a clientCredentials credential needs no user.", "properties.oauth2grantType")
		return
	}
	// An unknown action is a resource that does not exist, and must answer 404
	// whatever the service is configured with; the credential-engine check
	// belongs inside the actions that need it, not ahead of routing.
	switch strings.ToLower(action) {
	case "getloginlinks":
		if h.LoginLink == nil {
			writeError(w, http.StatusBadRequest, "ValidationError",
				"Credential manager is not configured on this service.", value.ID())
			return
		}
		var body struct {
			PostLoginRedirectURL string `json:"postLoginRedirectUrl"`
		}
		_ = decode(r, &body)
		link, err := h.LoginLink(authorization.ProviderID, authorization.ID(), body.PostLoginRedirectURL)
		if err != nil {
			writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"loginLink": link})
	case "confirmconsentcode":
		if h.ConfirmConsent == nil {
			writeError(w, http.StatusBadRequest, "ValidationError",
				"Credential manager is not configured on this service.", value.ID())
			return
		}
		var body struct {
			ConsentCode string `json:"consentCode"`
		}
		if err := decode(r, &body); err != nil || body.ConsentCode == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "properties.consentCode is required.", "consentCode")
			return
		}
		if err := h.ConfirmConsent(authorization.ProviderID, authorization.ID(), body.ConsentCode); err != nil {
			// The credential records WHY it is unusable, so an operator reading
			// the resource sees the provider's own refusal rather than having
			// to reproduce the exchange to find out.
			if _, ok := h.recordAuthorizationStatus(w, authorization, "Error", err.Error()); !ok {
				return
			}
			writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "consentCode")
			return
		}
		got, ok := h.recordAuthorizationStatus(w, authorization, "Connected", "")
		if !ok {
			return
		}
		writeResource(w, http.StatusOK, authorizationWire(got), got.ETag)
	default:
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The resource was not found.", value.ID())
	}
}

// recordAuthorizationStatus persists the outcome of a consent attempt.
//
// Shared by both paths because both must record it: a refusal is written so an
// operator reads the provider's own reason instead of reproducing the exchange,
// and a success is written so the credential stops reporting itself unusable.
// It reports whether the write succeeded, so a caller stops rather than
// answering as though the state had been saved.
func (h *Handler) recordAuthorizationStatus(w http.ResponseWriter, authorization model.Authorization, status, message string) (model.Authorization, bool) {
	authorization.Status, authorization.ErrorMsg = status, message
	got, err := h.Store.UpsertAuthorization(authorization)
	if err != nil {
		h.storeError(w, err, authorization.ID())
		return model.Authorization{}, false
	}
	return got, true
}
