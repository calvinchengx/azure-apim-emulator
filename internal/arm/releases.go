package arm

import (
	"errors"
	"net/http"
	"time"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

type apiReleasePayload struct {
	Properties struct {
		APIID *string `json:"apiId"`
		Notes *string `json:"notes"`
	} `json:"properties"`
}

func (h *Handler) apiReleaseResource(w http.ResponseWriter, r *http.Request, value model.APIRelease) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetAPIRelease(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, apiReleaseWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetAPIRelease(value.ID())
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
		var body apiReleasePayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = apiReleaseWire(value)
			}
			mergeObject(value.Document, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		if body.Properties.APIID != nil {
			_, targetID, err := h.revisionSource(*body.Properties.APIID)
			if err != nil {
				h.storeError(w, err, *body.Properties.APIID)
				return
			}
			value.TargetAPIID = targetID
		}
		if body.Properties.Notes != nil {
			value.Notes = *body.Properties.Notes
		}
		properties, _ := document["properties"].(map[string]any)
		if field, present := properties["apiId"]; present && field == nil {
			value.TargetAPIID = ""
		}
		if field, present := properties["notes"]; present && field == nil {
			value.Notes = ""
		}
		if value.TargetAPIID == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "apiId is required.", "properties.apiId")
			return
		}
		got, err := h.Store.UpsertAPIRelease(value)
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
		writeResource(w, status, apiReleaseWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteAPIRelease(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func apiReleaseWire(v model.APIRelease) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/apis/releases"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["apiId"], properties["notes"] = v.TargetAPIID, v.Notes
	properties["createdDateTime"] = time.Unix(v.CreatedAt, 0).UTC().Format(time.RFC3339)
	properties["updatedDateTime"] = time.Unix(v.UpdatedAt, 0).UTC().Format(time.RFC3339)
	return result
}
