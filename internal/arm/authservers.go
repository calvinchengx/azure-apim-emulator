package arm

import (
	"errors"
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

type authorizationServerPayload struct {
	Properties struct {
		DisplayName                *string  `json:"displayName"`
		Description                *string  `json:"description"`
		AuthorizationEndpoint      *string  `json:"authorizationEndpoint"`
		ClientRegistrationEndpoint *string  `json:"clientRegistrationEndpoint"`
		ClientID                   *string  `json:"clientId"`
		ClientSecret               *string  `json:"clientSecret"`
		TokenEndpoint              *string  `json:"tokenEndpoint"`
		DefaultScope               *string  `json:"defaultScope"`
		ResourceOwnerUsername      *string  `json:"resourceOwnerUsername"`
		ResourceOwnerPassword      *string  `json:"resourceOwnerPassword"`
		SupportState               *bool    `json:"supportState"`
		GrantTypes                 []string `json:"grantTypes"`
	} `json:"properties"`
}

var authorizationServerGrantTypes = map[string]bool{
	"authorizationCode":     true,
	"implicit":              true,
	"resourceOwnerPassword": true,
	"clientCredentials":     true,
}

func (h *Handler) authorizationServer(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListAuthorizationServers(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, authorizationServerWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) < 2 || len(rt.Tail) > 3 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested authorization server resource was not found.", r.URL.Path)
		return
	}
	value := model.AuthorizationServer{ServiceID: scope, Name: rt.Tail[1]}
	if len(rt.Tail) == 3 {
		h.authorizationServerAction(w, r, value, rt.Tail[2])
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetAuthorizationServer(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, authorizationServerWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetAuthorizationServer(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if existingErr == nil {
			value.Name = existing.Name
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, value.ID())
				return
			}
			value = existing
		}
		var body authorizationServerPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = authorizationServerWire(value)
			}
			mergeObject(value.Document, document)
			clearNullAuthorizationServerProperties(&value, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		sanitizeAuthorizationServerDocument(value.Document)
		applyAuthorizationServerPayload(&value, body)
		if err := validateAuthorizationServer(value, r.Method == http.MethodPut); err != nil {
			writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties")
			return
		}
		got, err := h.Store.UpsertAuthorizationServer(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, authorizationServerWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteAuthorizationServer(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) authorizationServerAction(w http.ResponseWriter, r *http.Request, value model.AuthorizationServer, action string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !equal(action, "listSecrets") {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested authorization server action was not found.", r.URL.Path)
		return
	}
	got, err := h.Store.GetAuthorizationServer(value.ID())
	if err != nil {
		h.storeError(w, err, value.ID())
		return
	}
	writeResource(w, http.StatusOK, map[string]any{
		"clientSecret":          got.ClientSecret,
		"resourceOwnerUsername": got.ResourceOwnerUsername,
		"resourceOwnerPassword": got.ResourceOwnerPassword,
	}, got.ETag)
}

func applyAuthorizationServerPayload(value *model.AuthorizationServer, body authorizationServerPayload) {
	if body.Properties.DisplayName != nil {
		value.DisplayName = *body.Properties.DisplayName
	}
	if body.Properties.Description != nil {
		value.Description = *body.Properties.Description
	}
	if body.Properties.AuthorizationEndpoint != nil {
		value.AuthorizationEndpoint = *body.Properties.AuthorizationEndpoint
	}
	if body.Properties.ClientRegistrationEndpoint != nil {
		value.ClientRegistrationEndpoint = *body.Properties.ClientRegistrationEndpoint
	}
	if body.Properties.ClientID != nil {
		value.ClientID = *body.Properties.ClientID
	}
	if body.Properties.ClientSecret != nil {
		value.ClientSecret = *body.Properties.ClientSecret
	}
	if body.Properties.TokenEndpoint != nil {
		value.TokenEndpoint = *body.Properties.TokenEndpoint
	}
	if body.Properties.DefaultScope != nil {
		value.DefaultScope = *body.Properties.DefaultScope
	}
	if body.Properties.ResourceOwnerUsername != nil {
		value.ResourceOwnerUsername = *body.Properties.ResourceOwnerUsername
	}
	if body.Properties.ResourceOwnerPassword != nil {
		value.ResourceOwnerPassword = *body.Properties.ResourceOwnerPassword
	}
	if body.Properties.SupportState != nil {
		value.SupportState = *body.Properties.SupportState
	}
	if body.Properties.GrantTypes != nil {
		value.GrantTypes = append([]string(nil), body.Properties.GrantTypes...)
	}
}

func clearNullAuthorizationServerProperties(value *model.AuthorizationServer, document map[string]any) {
	properties, _ := document["properties"].(map[string]any)
	if field, present := properties["description"]; present && field == nil {
		value.Description = ""
	}
	if field, present := properties["tokenEndpoint"]; present && field == nil {
		value.TokenEndpoint = ""
	}
	if field, present := properties["defaultScope"]; present && field == nil {
		value.DefaultScope = ""
	}
	if field, present := properties["resourceOwnerUsername"]; present && field == nil {
		value.ResourceOwnerUsername = ""
	}
	if field, present := properties["resourceOwnerPassword"]; present && field == nil {
		value.ResourceOwnerPassword = ""
	}
	if field, present := properties["supportState"]; present && field == nil {
		value.SupportState = false
	}
}

func validateAuthorizationServer(value model.AuthorizationServer, creating bool) error {
	if creating && value.DisplayName == "" {
		return errors.New("displayName is required")
	}
	if creating && value.AuthorizationEndpoint == "" {
		return errors.New("authorizationEndpoint is required")
	}
	if creating && value.ClientRegistrationEndpoint == "" {
		return errors.New("clientRegistrationEndpoint is required")
	}
	if creating && value.ClientID == "" {
		return errors.New("clientId is required")
	}
	if creating && len(value.GrantTypes) == 0 {
		return errors.New("grantTypes is required")
	}
	if value.DisplayName == "" {
		return errors.New("displayName cannot be empty")
	}
	if len(value.DisplayName) > 50 {
		return errors.New("displayName must be at most 50 characters")
	}
	if value.AuthorizationEndpoint == "" {
		return errors.New("authorizationEndpoint cannot be empty")
	}
	if value.ClientRegistrationEndpoint == "" {
		return errors.New("clientRegistrationEndpoint cannot be empty")
	}
	if value.ClientID == "" {
		return errors.New("clientId cannot be empty")
	}
	if len(value.GrantTypes) == 0 {
		return errors.New("grantTypes cannot be empty")
	}
	for _, grant := range value.GrantTypes {
		if !authorizationServerGrantTypes[grant] {
			return errors.New("grantTypes must be authorizationCode, implicit, resourceOwnerPassword, or clientCredentials")
		}
	}
	if methods := authorizationServerMethods(value.Document); len(methods) > 0 {
		hasGET := false
		for _, method := range methods {
			if strings.EqualFold(method, http.MethodGet) {
				hasGET = true
				break
			}
		}
		if !hasGET {
			return errors.New("authorizationMethods must include GET")
		}
	}
	return nil
}

func authorizationServerMethods(document map[string]any) []string {
	properties, _ := document["properties"].(map[string]any)
	raw, _ := properties["authorizationMethods"].([]any)
	methods := make([]string, 0, len(raw))
	for _, value := range raw {
		method, _ := value.(string)
		if method != "" {
			methods = append(methods, method)
		}
	}
	return methods
}

func sanitizeAuthorizationServerDocument(document map[string]any) {
	if document == nil {
		return
	}
	delete(document, "clientSecret")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "clientSecret")
}

func authorizationServerWire(v model.AuthorizationServer) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/authorizationServers"
	delete(result, "clientSecret")
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	delete(properties, "clientSecret")
	grants := v.GrantTypes
	if grants == nil {
		grants = []string{}
	}
	properties["displayName"] = v.DisplayName
	properties["description"] = v.Description
	properties["authorizationEndpoint"] = v.AuthorizationEndpoint
	properties["clientRegistrationEndpoint"] = v.ClientRegistrationEndpoint
	properties["clientId"] = v.ClientID
	properties["tokenEndpoint"] = v.TokenEndpoint
	properties["defaultScope"] = v.DefaultScope
	properties["resourceOwnerUsername"] = v.ResourceOwnerUsername
	properties["resourceOwnerPassword"] = v.ResourceOwnerPassword
	properties["supportState"] = v.SupportState
	properties["grantTypes"] = grants
	return result
}
