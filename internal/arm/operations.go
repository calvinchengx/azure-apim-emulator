package arm

import (
	"errors"
	"net/http"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

type operationPayload struct {
	Properties struct {
		DisplayName *string `json:"displayName"`
		Method      *string `json:"method"`
		URLTemplate *string `json:"urlTemplate"`
	} `json:"properties"`
}

func (h *Handler) operationResource(w http.ResponseWriter, r *http.Request, operation model.Operation) {
	id := operation.APIID + "/operations/" + operation.Name
	switch r.Method {
	case http.MethodGet:
		got, err := h.Store.GetOperation(id)
		if err != nil {
			h.storeError(w, err, id)
			return
		}
		writeResource(w, http.StatusOK, operationWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetOperation(id)
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, id)
			return
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, id)
				return
			}
			operation = existing
		}
		var body operationPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if operation.Document == nil {
				operation.Document = operationWire(operation)
			}
			mergeObject(operation.Document, document)
		} else {
			operation.Document = document
		}
		cleanResourceDocument(operation.Document)
		applyOperationPayload(&operation, body)
		if operation.Method == "" || operation.URLTemplate == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "method and urlTemplate are required.", "properties")
			return
		}
		got, err := h.Store.UpsertOperation(operation)
		if err != nil {
			h.storeError(w, err, id)
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), id)
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, operationWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteOperation(id); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, id)
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), id)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func applyOperationPayload(operation *model.Operation, body operationPayload) {
	if body.Properties.DisplayName != nil {
		operation.DisplayName = *body.Properties.DisplayName
	}
	if body.Properties.Method != nil {
		operation.Method = *body.Properties.Method
	}
	if body.Properties.URLTemplate != nil {
		operation.URLTemplate = *body.Properties.URLTemplate
	}
}

func operationWire(v model.Operation) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.APIID+"/operations/"+v.Name, v.Name, "Microsoft.ApiManagement/service/apis/operations"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["displayName"], properties["method"], properties["urlTemplate"] = v.DisplayName, v.Method, v.URLTemplate
	return result
}
