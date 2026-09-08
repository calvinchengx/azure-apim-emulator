package arm

import (
	"errors"
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

type identityProviderPayload struct {
	Properties struct {
		Type                     *string   `json:"type"`
		ClientID                 *string   `json:"clientId"`
		ClientSecret             *string   `json:"clientSecret"`
		Authority                *string   `json:"authority"`
		SigninTenant             *string   `json:"signinTenant"`
		SignupPolicyName         *string   `json:"signupPolicyName"`
		SigninPolicyName         *string   `json:"signinPolicyName"`
		ProfileEditingPolicyName *string   `json:"profileEditingPolicyName"`
		PasswordResetPolicyName  *string   `json:"passwordResetPolicyName"`
		AllowedTenants           *[]string `json:"allowedTenants"`
		ClientLibrary            *string   `json:"clientLibrary"`
	} `json:"properties"`
}

var identityProviderNames = map[string]string{
	"facebook":  "facebook",
	"google":    "google",
	"microsoft": "microsoft",
	"twitter":   "twitter",
	"aad":       "aad",
	"aadb2c":    "aadB2C",
}

func canonicalizeIdentityProviderName(name string) (string, bool) {
	canonical, ok := identityProviderNames[strings.ToLower(name)]
	return canonical, ok
}

func (h *Handler) identityProvider(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListIdentityProviders(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, identityProviderWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) < 2 || len(rt.Tail) > 3 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested identity provider resource was not found.", r.URL.Path)
		return
	}
	name, ok := canonicalizeIdentityProviderName(rt.Tail[1])
	if !ok {
		writeError(w, http.StatusBadRequest, "ValidationError", "identityProviderName must be facebook, google, microsoft, twitter, aad, or aadB2C.", "identityProviderName")
		return
	}
	value := model.IdentityProvider{ServiceID: scope, Name: name}
	if len(rt.Tail) == 3 {
		h.identityProviderAction(w, r, value, rt.Tail[2])
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetIdentityProvider(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, identityProviderWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetIdentityProvider(value.ID())
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
		var body identityProviderPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if body.Properties.Type != nil {
			canonical, typeOK := canonicalizeIdentityProviderName(*body.Properties.Type)
			if !typeOK || canonical != value.Name {
				writeError(w, http.StatusBadRequest, "ValidationError", "type must match the identity provider name.", "properties.type")
				return
			}
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = identityProviderWire(value)
			}
			mergeObject(value.Document, document)
			clearNullIdentityProviderProperties(&value, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		sanitizeIdentityProviderDocument(value.Document)
		applyIdentityProviderPayload(&value, body)
		if err := validateIdentityProvider(value, r.Method == http.MethodPut); err != nil {
			writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties")
			return
		}
		got, err := h.Store.UpsertIdentityProvider(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, identityProviderWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteIdentityProvider(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) identityProviderAction(w http.ResponseWriter, r *http.Request, value model.IdentityProvider, action string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !equal(action, "listSecrets") {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested identity provider action was not found.", r.URL.Path)
		return
	}
	got, err := h.Store.GetIdentityProvider(value.ID())
	if err != nil {
		h.storeError(w, err, value.ID())
		return
	}
	writeResource(w, http.StatusOK, map[string]any{"clientSecret": got.ClientSecret}, got.ETag)
}

func applyIdentityProviderPayload(value *model.IdentityProvider, body identityProviderPayload) {
	if body.Properties.ClientID != nil {
		value.ClientID = *body.Properties.ClientID
	}
	if body.Properties.ClientSecret != nil {
		value.ClientSecret = *body.Properties.ClientSecret
	}
	if body.Properties.Authority != nil {
		value.Authority = *body.Properties.Authority
	}
	if body.Properties.SigninTenant != nil {
		value.SigninTenant = *body.Properties.SigninTenant
	}
	if body.Properties.SignupPolicyName != nil {
		value.SignupPolicyName = *body.Properties.SignupPolicyName
	}
	if body.Properties.SigninPolicyName != nil {
		value.SigninPolicyName = *body.Properties.SigninPolicyName
	}
	if body.Properties.ProfileEditingPolicyName != nil {
		value.ProfileEditingPolicyName = *body.Properties.ProfileEditingPolicyName
	}
	if body.Properties.PasswordResetPolicyName != nil {
		value.PasswordResetPolicyName = *body.Properties.PasswordResetPolicyName
	}
	if body.Properties.AllowedTenants != nil {
		value.AllowedTenants = append([]string(nil), *body.Properties.AllowedTenants...)
	}
}

func clearNullIdentityProviderProperties(value *model.IdentityProvider, document map[string]any) {
	properties, _ := document["properties"].(map[string]any)
	if field, present := properties["authority"]; present && field == nil {
		value.Authority = ""
	}
	if field, present := properties["signinTenant"]; present && field == nil {
		value.SigninTenant = ""
	}
	if field, present := properties["signupPolicyName"]; present && field == nil {
		value.SignupPolicyName = ""
	}
	if field, present := properties["signinPolicyName"]; present && field == nil {
		value.SigninPolicyName = ""
	}
	if field, present := properties["profileEditingPolicyName"]; present && field == nil {
		value.ProfileEditingPolicyName = ""
	}
	if field, present := properties["passwordResetPolicyName"]; present && field == nil {
		value.PasswordResetPolicyName = ""
	}
	if field, present := properties["allowedTenants"]; present && field == nil {
		value.AllowedTenants = []string{}
	}
}

func validateIdentityProvider(value model.IdentityProvider, creating bool) error {
	if creating && value.ClientID == "" {
		return errors.New("clientId is required")
	}
	if creating && value.ClientSecret == "" {
		return errors.New("clientSecret is required")
	}
	if value.ClientID == "" {
		return errors.New("clientId cannot be empty")
	}
	if value.ClientSecret == "" {
		return errors.New("clientSecret cannot be empty")
	}
	if library := identityProviderClientLibrary(value.Document); len(library) > 16 {
		return errors.New("clientLibrary must be at most 16 characters")
	}
	return nil
}

func identityProviderClientLibrary(document map[string]any) string {
	properties, _ := document["properties"].(map[string]any)
	value, _ := properties["clientLibrary"].(string)
	return value
}

func sanitizeIdentityProviderDocument(document map[string]any) {
	if document == nil {
		return
	}
	delete(document, "clientSecret")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "clientSecret")
}

func identityProviderWire(v model.IdentityProvider) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/identityProviders"
	delete(result, "clientSecret")
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	delete(properties, "clientSecret")
	tenants := v.AllowedTenants
	if tenants == nil {
		tenants = []string{}
	}
	properties["type"] = v.Name
	properties["clientId"] = v.ClientID
	properties["allowedTenants"] = tenants
	properties["authority"] = v.Authority
	properties["signinTenant"] = v.SigninTenant
	properties["signupPolicyName"] = v.SignupPolicyName
	properties["signinPolicyName"] = v.SigninPolicyName
	properties["profileEditingPolicyName"] = v.ProfileEditingPolicyName
	properties["passwordResetPolicyName"] = v.PasswordResetPolicyName
	return result
}
