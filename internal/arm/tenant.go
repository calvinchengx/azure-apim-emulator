package arm

import (
	"errors"
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

// tenantAccess serves `/tenant` and `/tenant/{accessName}` and everything under
// it. Four contract facts drive the shape here, all read off
// `@azure/arm-apimanagement@10.0.0` rather than assumed by analogy with the
// collection families around it:
//
//   - `AccessIdName` has exactly TWO members, `access` and `gitAccess`, and no
//     operation creates or deletes either. They are seeded with the service, so
//     an unknown accessName is a 404 rather than an implicit create.
//   - `Create` (PUT) declares ONLY a 200 response. Returning the 201 that every
//     other create in this provider returns would be an undeclared status the
//     SDK refuses to deserialize.
//   - `ifMatch` is REQUIRED on both PUT and PATCH, unlike the optional If-Match
//     everywhere else. See requiresIfMatch.
//   - GET must not carry the keys. Microsoft models the two responses as two
//     different types for that reason, and the `/listSecrets` one is not even
//     wrapped in `properties`.
func (h *Handler) tenantAccess(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		if err := h.requireScope(rt); err != nil {
			h.storeError(w, err, scope)
			return
		}
		values, err := h.Store.ListTenantAccess(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, tenantAccessWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	// `/tenant/{accessName}/git/regenerate*` is the TenantAccessGit group, and
	// the `git` segment is what selects the target: the operation is
	// "Regenerate primary access key for GIT", so it regenerates the gitAccess
	// row whatever accessName the caller routed through. Anything else nested
	// under an access configuration does not exist.
	switch {
	case len(rt.Tail) == 2:
	case len(rt.Tail) == 3 && oneOf(strings.ToLower(rt.Tail[2]), "regenerateprimarykey", "regeneratesecondarykey", "listsecrets"):
	case len(rt.Tail) == 4 && equal(rt.Tail[2], "git") && oneOf(strings.ToLower(rt.Tail[3]), "regenerateprimarykey", "regeneratesecondarykey"):
	default:
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested tenant access resource was not found.", r.URL.Path)
		return
	}
	name, err := tenantAccessName(rt.Tail[1])
	if err != nil {
		writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "accessName")
		return
	}
	if len(rt.Tail) == 4 {
		name = "gitAccess"
	}
	id := model.TenantAccess{ServiceID: scope, Name: name}.ID()
	if len(rt.Tail) > 2 {
		h.tenantAccessAction(w, r, id, strings.ToLower(rt.Tail[len(rt.Tail)-1]))
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetTenantAccess(id)
		if err != nil {
			h.storeError(w, err, id)
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, tenantAccessWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, err := h.Store.GetTenantAccess(id)
		if err != nil {
			h.storeError(w, err, id)
			return
		}
		var body struct {
			Properties struct {
				PrincipalID  *string `json:"principalId"`
				PrimaryKey   *string `json:"primaryKey"`
				SecondaryKey *string `json:"secondaryKey"`
				Enabled      *bool   `json:"enabled"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		// PATCH carries `AccessInformationUpdateParameters`, whose only member
		// is `enabled`. A caller sending a key there is trying to set one
		// through a door Azure does not open, so say so rather than silently
		// keeping the old value and reporting success.
		if r.Method == http.MethodPatch {
			for field, sent := range map[string]bool{
				"principalId":  body.Properties.PrincipalID != nil,
				"primaryKey":   body.Properties.PrimaryKey != nil,
				"secondaryKey": body.Properties.SecondaryKey != nil,
			} {
				if sent {
					writeError(w, http.StatusBadRequest, "ValidationError",
						"properties."+field+" cannot be set by an update; the update contract carries enabled only.",
						"properties."+field)
					return
				}
			}
		}
		value := existing
		if body.Properties.Enabled != nil {
			value.Enabled = *body.Properties.Enabled
		}
		if r.Method == http.MethodPut {
			if body.Properties.PrincipalID != nil {
				value.PrincipalID = *body.Properties.PrincipalID
			}
			if body.Properties.PrimaryKey != nil {
				value.PrimaryKey = *body.Properties.PrimaryKey
			}
			if body.Properties.SecondaryKey != nil {
				value.SecondaryKey = *body.Properties.SecondaryKey
			}
		}
		got, err := h.Store.UpsertTenantAccess(value)
		if err != nil {
			h.storeError(w, err, id)
			return
		}
		// 200, never 201: `Create` declares no other success status.
		writeResource(w, http.StatusOK, tenantAccessWire(got), got.ETag)
	default:
		methodNotAllowed(w)
	}
}

// tenantAccessAction serves the three POST verbs. Both regenerate operations
// declare 204 with no body; listSecrets declares 200 with an UNWRAPPED body.
func (h *Handler) tenantAccessAction(w http.ResponseWriter, r *http.Request, id, action string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	got, err := h.Store.GetTenantAccess(id)
	if err != nil {
		h.storeError(w, err, id)
		return
	}
	if action == "listsecrets" {
		// Flat, with no `properties` envelope: `AccessInformationSecretsContract`
		// serializes every field at the top level, and it is the only response
		// in this provider that does.
		secrets := map[string]any{
			"id":           got.Name,
			"primaryKey":   got.PrimaryKey,
			"secondaryKey": got.SecondaryKey,
			"enabled":      got.Enabled,
		}
		if got.PrincipalID != "" {
			secrets["principalId"] = got.PrincipalID
		}
		writeResource(w, http.StatusOK, secrets, got.ETag)
		return
	}
	if action == "regenerateprimarykey" {
		got.PrimaryKey = store.NewAccessKey()
	} else {
		got.SecondaryKey = store.NewAccessKey()
	}
	if _, err := h.Store.UpsertTenantAccess(got); err != nil {
		h.storeError(w, err, id)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// tenantAccessName resolves the `accessName` path segment against Microsoft's
// enum. Matching case-insensitively but returning the CANONICAL spelling is
// what keeps `/tenant/gitaccess` and `/tenant/gitAccess` the same row while the
// resource still reports the name Azure reports.
func tenantAccessName(value string) (string, error) {
	for _, name := range []string{"access", "gitAccess"} {
		if equal(value, name) {
			return name, nil
		}
	}
	return "", errors.New("accessName must be access or gitAccess")
}

func tenantAccessWire(v model.TenantAccess) map[string]any {
	properties := map[string]any{
		// `properties.id` really is the access NAME, not the resource id. The
		// SDK renames it `idPropertiesId` precisely because it collides with
		// the ARM id one level up.
		"id":      v.Name,
		"enabled": v.Enabled,
	}
	// Absent rather than empty: the `access` configuration has no principal in
	// Azure's own example, and an empty string is a value a client can read.
	if v.PrincipalID != "" {
		properties["principalId"] = v.PrincipalID
	}
	// The keys are deliberately NOT here. `AccessInformationContract` has no
	// field for them, and `/listSecrets` is the only way out.
	return map[string]any{
		"id":         v.ID(),
		"name":       v.Name,
		"type":       "Microsoft.ApiManagement/service/tenant",
		"properties": properties,
	}
}

// tenantSettings serves `/settings` and `/settings/{settingsType}`.
//
// Read-only, and a singleton: `SettingsTypeName` has one member, `public`, and
// the SDK publishes only `listByService` and `get`. The values are the ones a
// fresh service returns.
//
// This is a PROJECTION in Azure: each key mirrors a portal setting that the
// SignInSettings/SignUpSettings/DelegationSettings operations own. Those are in
// the deferred developer-portal group, so nothing here can move yet and the
// defaults are the whole truth. When those land, this must read them rather
// than keep returning constants, or it becomes a surface that agrees with
// itself and with nothing else.
func (h *Handler) tenantSettings(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w)
		return
	}
	service, err := h.Store.GetService(rt.service().ID())
	if err != nil {
		h.storeError(w, err, scope)
		return
	}
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": []any{tenantSettingsWire(scope)}})
		return
	}
	if len(rt.Tail) != 2 || !equal(rt.Tail[1], "public") {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "settingsType must be public.", r.URL.Path)
		return
	}
	// The settings are derived, so they change exactly when the service does;
	// borrowing the service's entity tag says that honestly instead of minting
	// a fresh one that implies an edit nobody made.
	if r.Method == http.MethodHead {
		w.Header().Set("ETag", service.ETag)
		w.WriteHeader(http.StatusOK)
		return
	}
	writeResource(w, http.StatusOK, tenantSettingsWire(scope), service.ETag)
}

func tenantSettingsWire(scope string) map[string]any {
	return map[string]any{
		"id":   scope + "/settings/public",
		"name": "public",
		"type": "Microsoft.ApiManagement/service/settings",
		"properties": map[string]any{
			"settings": map[string]any{
				// null, not "", and it is Azure's own example that says so.
				"CustomPortalSettings.UserRegistrationTerms":                nil,
				"CustomPortalSettings.UserRegistrationTermsEnabled":         "False",
				"CustomPortalSettings.UserRegistrationTermsConsentRequired": "False",
				"CustomPortalSettings.DelegationEnabled":                    "False",
				"CustomPortalSettings.DelegationUrl":                        "",
				"CustomPortalSettings.DelegatedSubscriptionEnabled":         "False",
			},
		},
	}
}
