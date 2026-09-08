package arm

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

func (h *Handler) user(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListUsers(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, userWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	value := model.User{ServiceID: scope, Name: rt.Tail[1], State: "active"}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "groups") {
		if _, err := h.Store.GetUser(value.ID()); err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListUserGroups(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, group := range values {
			resources = append(resources, groupWire(group))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "generateSsoUrl") {
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		got, err := h.Store.GetUser(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		expiry := time.Unix(h.Store.Clock.Now(), 0).Add(5 * time.Minute)
		token := userToken(got, "primary", expiry)
		writeJSON(w, http.StatusOK, map[string]any{"value": absolute(r, "/signin-sso?token="+url.QueryEscape(token))})
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "token") {
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		got, err := h.Store.GetUser(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		var body struct {
			Properties struct {
				KeyType string    `json:"keyType"`
				Expiry  time.Time `json:"expiry"`
			} `json:"properties"`
		}
		if err := decode(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		now := time.Unix(h.Store.Clock.Now(), 0)
		if body.Properties.KeyType != "primary" && body.Properties.KeyType != "secondary" {
			writeError(w, http.StatusBadRequest, "ValidationError", "keyType must be primary or secondary.", "properties.keyType")
			return
		}
		if !body.Properties.Expiry.After(now) || body.Properties.Expiry.After(now.Add(30*24*time.Hour)) {
			writeError(w, http.StatusBadRequest, "ValidationError", "expiry must be in the next 30 days.", "properties.expiry")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": userToken(got, body.Properties.KeyType, body.Properties.Expiry)})
		return
	}
	if len(rt.Tail) != 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested user resource was not found.", r.URL.Path)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetUser(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, userWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetUser(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if existingErr == nil {
			value = existing
		} else if r.Method == http.MethodPatch {
			h.storeError(w, existingErr, value.ID())
			return
		}
		var body struct {
			Properties struct {
				FirstName  *string               `json:"firstName"`
				LastName   *string               `json:"lastName"`
				Email      *string               `json:"email"`
				State      *string               `json:"state"`
				Note       *string               `json:"note"`
				Password   *string               `json:"password"`
				Identities *[]model.UserIdentity `json:"identities"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = userWire(value)
			}
			mergeObject(value.Document, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		sanitizeUserDocument(value.Document)
		if body.Properties.FirstName != nil {
			value.FirstName = *body.Properties.FirstName
		}
		if body.Properties.LastName != nil {
			value.LastName = *body.Properties.LastName
		}
		if body.Properties.Email != nil {
			value.Email = *body.Properties.Email
		}
		if body.Properties.State != nil {
			value.State = *body.Properties.State
		}
		if body.Properties.Note != nil {
			value.Note = *body.Properties.Note
		}
		if body.Properties.Password != nil {
			value.Password = *body.Properties.Password
		}
		if body.Properties.Identities != nil {
			value.Identities = *body.Properties.Identities
		}
		clearNullUserProperties(&value, document)
		if strings.TrimSpace(value.FirstName) == "" || strings.TrimSpace(value.LastName) == "" || strings.TrimSpace(value.Email) == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "firstName, lastName, and email are required.", "properties")
			return
		}
		if value.State != "active" && value.State != "blocked" && value.State != "deleted" && value.State != "pending" {
			writeError(w, http.StatusBadRequest, "ValidationError", "invalid user state.", "properties.state")
			return
		}
		got, err := h.Store.UpsertUser(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, userWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteUser(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func userToken(user model.User, keyType string, expiry time.Time) string {
	key := user.PrimaryKey
	if keyType == "secondary" {
		key = user.SecondaryKey
	}
	expires := expiry.UTC().Format(time.RFC3339)
	message := user.ID() + "\n" + expires
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(message))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return "SharedAccessSignature uid=" + url.QueryEscape(user.ID()) + "&ex=" + url.QueryEscape(expires) + "&sn=" + url.QueryEscape(user.Name) + "&skn=" + keyType + "&sig=" + url.QueryEscape(signature)
}

func userWire(v model.User) map[string]any {
	identities := make([]map[string]any, 0, len(v.Identities))
	for _, identity := range v.Identities {
		identities = append(identities, map[string]any{"provider": identity.Provider, "id": identity.ID})
	}
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/users"
	delete(result, "password")
	delete(result, "primaryKey")
	delete(result, "secondaryKey")
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	delete(properties, "password")
	delete(properties, "primaryKey")
	delete(properties, "secondaryKey")
	properties["firstName"], properties["lastName"], properties["email"] = v.FirstName, v.LastName, v.Email
	properties["state"], properties["note"], properties["identities"] = v.State, v.Note, identities
	properties["registrationDate"] = time.Unix(v.RegistrationAt, 0).UTC().Format(time.RFC3339)
	return result
}

func sanitizeUserDocument(document map[string]any) {
	delete(document, "password")
	delete(document, "primaryKey")
	delete(document, "secondaryKey")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "password")
	delete(properties, "primaryKey")
	delete(properties, "secondaryKey")
}

func clearNullUserProperties(value *model.User, patch map[string]any) {
	properties, _ := patch["properties"].(map[string]any)
	if field, present := properties["firstName"]; present && field == nil {
		value.FirstName = ""
	}
	if field, present := properties["lastName"]; present && field == nil {
		value.LastName = ""
	}
	if field, present := properties["email"]; present && field == nil {
		value.Email = ""
	}
	if field, present := properties["state"]; present && field == nil {
		value.State = ""
	}
	if field, present := properties["note"]; present && field == nil {
		value.Note = ""
	}
	if field, present := properties["identities"]; present && field == nil {
		value.Identities = nil
	}
}
