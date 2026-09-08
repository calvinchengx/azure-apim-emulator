package arm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

type loggerPayload struct {
	Properties struct {
		LoggerType  *string           `json:"loggerType"`
		Description *string           `json:"description"`
		IsBuffered  *bool             `json:"isBuffered"`
		ResourceID  *string           `json:"resourceId"`
		Credentials map[string]string `json:"credentials"`
	} `json:"properties"`
}

func (h *Handler) logger(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListLoggers(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, loggerWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) != 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested logger resource was not found.", r.URL.Path)
		return
	}
	value := model.Logger{ServiceID: scope, Name: rt.Tail[1], IsBuffered: true}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetLogger(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, loggerWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetLogger(value.ID())
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
		var body loggerPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			mergeObject(value.Document, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		sanitizeLoggerDocument(value.Document)
		applyLoggerPayload(&value, body)
		if value.LoggerType != "applicationInsights" && value.LoggerType != "azureEventHub" && value.LoggerType != "azureMonitor" {
			writeError(w, http.StatusBadRequest, "ValidationError", "loggerType must be applicationInsights, azureEventHub, or azureMonitor.", "properties.loggerType")
			return
		}
		got, err := h.Store.UpsertLogger(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, loggerWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteLogger(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			if errors.Is(err, store.ErrConflict) {
				writeError(w, http.StatusConflict, "ResourceInUse", "The logger is referenced by a diagnostic.", value.ID())
				return
			}
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func applyLoggerPayload(value *model.Logger, body loggerPayload) {
	if body.Properties.LoggerType != nil {
		value.LoggerType = *body.Properties.LoggerType
	}
	if body.Properties.Description != nil {
		value.Description = *body.Properties.Description
	}
	if body.Properties.IsBuffered != nil {
		value.IsBuffered = *body.Properties.IsBuffered
	}
	if body.Properties.ResourceID != nil {
		value.ResourceID = *body.Properties.ResourceID
	}
	if body.Properties.Credentials != nil {
		value.Credentials = body.Properties.Credentials
	}
}

func sanitizeLoggerDocument(document map[string]any) {
	delete(document, "credentials")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "credentials")
}

func loggerWire(v model.Logger) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/loggers"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["loggerType"], properties["description"] = v.LoggerType, v.Description
	properties["isBuffered"], properties["resourceId"], properties["credentials"] = v.IsBuffered, v.ResourceID, loggerCredentialReferences(v.Credentials)
	return result
}

func loggerCredentialReferences(credentials map[string]string) map[string]string {
	result := make(map[string]string, len(credentials))
	for name, value := range credentials {
		if strings.HasPrefix(value, "{{") && strings.HasSuffix(value, "}}") {
			result[name] = value
			continue
		}
		digest := sha256.Sum256([]byte(value))
		result[name] = fmt.Sprintf("{{Logger-Credentials-%x}}", digest[:8])
	}
	return result
}
