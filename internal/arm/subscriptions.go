package arm

import (
	"errors"
	"net/http"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

func (h *Handler) subscription(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListSubscriptions(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, subscriptionWire(value, false))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources})
		return
	}
	value := model.Subscription{ServiceID: scope, Name: rt.Tail[1]}
	if len(rt.Tail) == 2 {
		h.subscriptionResource(w, r, value)
		return
	}
	if len(rt.Tail) != 3 || r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested subscription resource was not found.", r.URL.Path)
		return
	}
	switch rt.Tail[2] {
	case "listSecrets":
		got, err := h.Store.GetSubscription(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		writeResource(w, http.StatusOK, subscriptionSecretsWire(got), got.ETag)
	case "regeneratePrimaryKey", "regenerateSecondaryKey":
		got, err := h.Store.RegenerateSubscriptionKey(value.ID(), rt.Tail[2] == "regeneratePrimaryKey")
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		w.Header().Set("ETag", got.ETag)
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested subscription action was not found.", r.URL.Path)
	}
}

type subscriptionPayload struct {
	Properties struct {
		DisplayName  *string `json:"displayName"`
		Scope        *string `json:"scope"`
		State        *string `json:"state"`
		PrimaryKey   *string `json:"primaryKey"`
		SecondaryKey *string `json:"secondaryKey"`
	} `json:"properties"`
}

func (h *Handler) subscriptionResource(w http.ResponseWriter, r *http.Request, value model.Subscription) {
	switch r.Method {
	case http.MethodGet:
		got, err := h.Store.GetSubscription(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		writeResource(w, http.StatusOK, subscriptionWire(got, false), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetSubscription(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if r.Method == http.MethodPatch && errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		if existingErr == nil {
			value = existing
		}
		var body subscriptionPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			// The store guarantees a document to merge into, including for a
			// subscription stored before documents were written.
			mergeObject(value.Document, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		sanitizeSubscriptionDocument(value.Document)
		applySubscriptionPayload(&value, body)
		clearNullSubscriptionProperties(&value, document)
		if value.DisplayName == "" || value.Scope == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "displayName and scope are required.", "properties")
			return
		}
		got, err := h.Store.UpsertSubscription(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, subscriptionWire(got, false), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteSubscription(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func applySubscriptionPayload(value *model.Subscription, body subscriptionPayload) {
	if body.Properties.DisplayName != nil {
		value.DisplayName = *body.Properties.DisplayName
	}
	if body.Properties.Scope != nil {
		value.Scope = *body.Properties.Scope
	}
	if body.Properties.State != nil {
		value.State = *body.Properties.State
	}
	if body.Properties.PrimaryKey != nil {
		value.PrimaryKey = *body.Properties.PrimaryKey
	}
	if body.Properties.SecondaryKey != nil {
		value.SecondaryKey = *body.Properties.SecondaryKey
	}
}

func sanitizeSubscriptionDocument(document map[string]any) {
	delete(document, "primaryKey")
	delete(document, "secondaryKey")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "primaryKey")
	delete(properties, "secondaryKey")
}

func clearNullSubscriptionProperties(value *model.Subscription, patch map[string]any) {
	properties, _ := patch["properties"].(map[string]any)
	if field, present := properties["displayName"]; present && field == nil {
		value.DisplayName = ""
	}
	if field, present := properties["scope"]; present && field == nil {
		value.Scope = ""
	}
	if field, present := properties["state"]; present && field == nil {
		value.State = ""
	}
}

func subscriptionWire(v model.Subscription, secrets bool) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/subscriptions"
	delete(result, "primaryKey")
	delete(result, "secondaryKey")
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	delete(properties, "primaryKey")
	delete(properties, "secondaryKey")
	properties["displayName"], properties["scope"], properties["state"] = v.DisplayName, v.Scope, v.State
	if secrets {
		properties["primaryKey"], properties["secondaryKey"] = v.PrimaryKey, v.SecondaryKey
	}
	return result
}

func subscriptionSecretsWire(v model.Subscription) map[string]any {
	return map[string]any{"primaryKey": v.PrimaryKey, "secondaryKey": v.SecondaryKey}
}
