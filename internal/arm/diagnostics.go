package arm

import (
	"errors"
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

type diagnosticPayload struct {
	Properties struct {
		LoggerID    *string `json:"loggerId"`
		AlwaysLog   *string `json:"alwaysLog"`
		LogClientIP *bool   `json:"logClientIp"`
		Verbosity   *string `json:"verbosity"`
		Sampling    *struct {
			SamplingType *string  `json:"samplingType"`
			Percentage   *float64 `json:"percentage"`
		} `json:"sampling"`
	} `json:"properties"`
}

func (h *Handler) diagnostic(w http.ResponseWriter, r *http.Request, rt route, scopeID string, tailOffset int) {
	serviceID := model.Service{SubscriptionID: rt.SubscriptionID, ResourceGroup: rt.ResourceGroup, Name: rt.ServiceName}.ID()
	if len(rt.Tail) == tailOffset {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListDiagnostics(scopeID)
		if err != nil {
			h.storeError(w, err, scopeID)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, diagnosticWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) != tailOffset+1 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested diagnostic resource was not found.", r.URL.Path)
		return
	}
	value := model.Diagnostic{ServiceID: serviceID, ScopeID: scopeID, Name: rt.Tail[tailOffset], SamplingType: "fixed", SamplingPercentage: 100}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetDiagnostic(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, diagnosticWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetDiagnostic(value.ID())
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
		var body diagnosticPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			mergeObject(value.Document, document)
			clearNullDiagnosticProperties(&value, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		applyDiagnosticPayload(&value, body)
		if value.LoggerID == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "loggerId is required.", "properties.loggerId")
			return
		}
		logger, err := h.Store.GetLogger(value.LoggerID)
		if err != nil || !strings.EqualFold(logger.ServiceID, serviceID) {
			writeError(w, http.StatusBadRequest, "ValidationError", "loggerId must reference a logger in this service.", "properties.loggerId")
			return
		}
		if value.SamplingType != "fixed" || value.SamplingPercentage < 0 || value.SamplingPercentage > 100 {
			writeError(w, http.StatusBadRequest, "ValidationError", "sampling must use fixed with percentage from 0 through 100.", "properties.sampling")
			return
		}
		if value.AlwaysLog != "" && value.AlwaysLog != "allErrors" {
			writeError(w, http.StatusBadRequest, "ValidationError", "alwaysLog must be allErrors.", "properties.alwaysLog")
			return
		}
		if value.Verbosity != "" && value.Verbosity != "error" && value.Verbosity != "information" && value.Verbosity != "verbose" {
			writeError(w, http.StatusBadRequest, "ValidationError", "verbosity is invalid.", "properties.verbosity")
			return
		}
		got, err := h.Store.UpsertDiagnostic(value)
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
		writeResource(w, status, diagnosticWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteDiagnostic(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
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

func applyDiagnosticPayload(value *model.Diagnostic, body diagnosticPayload) {
	if body.Properties.LoggerID != nil {
		value.LoggerID = *body.Properties.LoggerID
	}
	if body.Properties.AlwaysLog != nil {
		value.AlwaysLog = *body.Properties.AlwaysLog
	}
	if body.Properties.LogClientIP != nil {
		value.LogClientIP = *body.Properties.LogClientIP
	}
	if body.Properties.Verbosity != nil {
		value.Verbosity = *body.Properties.Verbosity
	}
	if body.Properties.Sampling != nil {
		if body.Properties.Sampling.SamplingType != nil {
			value.SamplingType = *body.Properties.Sampling.SamplingType
		}
		if body.Properties.Sampling.Percentage != nil {
			value.SamplingPercentage = *body.Properties.Sampling.Percentage
		}
	}
}

func clearNullDiagnosticProperties(value *model.Diagnostic, patch map[string]any) {
	properties, _ := patch["properties"].(map[string]any)
	if field, present := properties["loggerId"]; present && field == nil {
		value.LoggerID = ""
	}
	if field, present := properties["alwaysLog"]; present && field == nil {
		value.AlwaysLog = ""
	}
	if field, present := properties["logClientIp"]; present && field == nil {
		value.LogClientIP = false
	}
	if field, present := properties["verbosity"]; present && field == nil {
		value.Verbosity = ""
	}
	sampling, present := properties["sampling"]
	if present && sampling == nil {
		value.SamplingType, value.SamplingPercentage = "fixed", 100
		return
	}
	samplingObject, _ := sampling.(map[string]any)
	if field, present := samplingObject["samplingType"]; present && field == nil {
		value.SamplingType = "fixed"
	}
	if field, present := samplingObject["percentage"]; present && field == nil {
		value.SamplingPercentage = 100
	}
}

func diagnosticWire(v model.Diagnostic) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"] = v.ID(), v.Name
	result["type"] = "Microsoft.ApiManagement/service/diagnostics"
	if !strings.EqualFold(v.ScopeID, v.ServiceID) {
		result["type"] = "Microsoft.ApiManagement/service/apis/diagnostics"
	}
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["loggerId"], properties["alwaysLog"] = v.LoggerID, v.AlwaysLog
	properties["logClientIp"], properties["verbosity"] = v.LogClientIP, v.Verbosity
	properties["sampling"] = map[string]any{"samplingType": v.SamplingType, "percentage": v.SamplingPercentage}
	return result
}
