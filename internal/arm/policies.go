package arm

import (
	"errors"
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

func (h *Handler) policyFragment(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListPolicyFragments(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, policyFragmentWire(value, r.URL.Query().Get("format")))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	value := model.PolicyFragment{ServiceID: scope, Name: rt.Tail[1], Format: "xml", ProvisioningState: "Succeeded"}
	if len(rt.Tail) == 3 && (equal(rt.Tail[2], "references") || equal(rt.Tail[2], "listReferences")) {
		method := http.MethodGet
		if equal(rt.Tail[2], "listReferences") {
			method = http.MethodPost
		}
		if r.Method != method {
			methodNotAllowed(w)
			return
		}
		if _, err := h.Store.GetPolicyFragment(value.ID()); err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		references, err := h.Store.ListPolicyFragmentReferences(scope, value.Name)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		resources := make([]map[string]any, 0, len(references))
		for _, reference := range references {
			resources = append(resources, map[string]any{"id": reference.ScopeID, "name": "policy", "type": "Microsoft.ApiManagement/service/apis/policies"})
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) != 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested policy fragment resource was not found.", r.URL.Path)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetPolicyFragment(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, policyFragmentWire(got, r.URL.Query().Get("format")), got.ETag)
	case http.MethodPut:
		_, existingErr := h.Store.GetPolicyFragment(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		var body struct {
			Properties struct {
				Description string `json:"description"`
				Format      string `json:"format"`
				Value       string `json:"value"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		value.Document = document
		cleanResourceDocument(value.Document)
		if body.Properties.Format != "" {
			value.Format = body.Properties.Format
		}
		value.Description, value.Value = body.Properties.Description, body.Properties.Value
		if value.Format != "xml" && value.Format != "rawxml" {
			writeError(w, http.StatusBadRequest, "ValidationError", "format must be xml or rawxml.", "properties.format")
			return
		}
		if err := policy.ValidateFragment(value.Value); err != nil {
			writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties.value")
			return
		}
		got, err := h.Store.UpsertPolicyFragment(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		status := http.StatusOK
		if errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, policyFragmentWire(got, ""), got.ETag)
	case http.MethodDelete:
		references, err := h.Store.ListPolicyFragmentReferences(scope, value.Name)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if len(references) != 0 {
			writeError(w, http.StatusConflict, "ResourceInUse", "The policy fragment is referenced by a policy.", value.ID())
			return
		}
		if err := h.Store.DeletePolicyFragment(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
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

func policyFragmentWire(v model.PolicyFragment, format string) map[string]any {
	if format != "xml" && format != "rawxml" {
		format = v.Format
	}
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/policyFragments"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["description"], properties["format"], properties["value"] = v.Description, format, v.Value
	properties["provisioningState"] = v.ProvisioningState
	return result
}

func (h *Handler) policyResource(w http.ResponseWriter, r *http.Request, scopeID, armType string) {
	switch r.Method {
	case http.MethodGet:
		value, err := h.Store.GetPolicy(scopeID)
		if err != nil {
			h.storeError(w, err, scopeID)
			return
		}
		writeResource(w, http.StatusOK, policyWire(scopeID, armType, value), value.ETag)
	case http.MethodPut:
		var body struct {
			Properties struct {
				Format string `json:"format"`
				Value  string `json:"value"`
			} `json:"properties"`
		}
		if err := decode(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		// A resolver's policy is a different document: its root is
		// <http-data-source>, not <policies>. Validating it as a policy would
		// reject every resolver Azure's own portal produces.
		validate := h.ValidatePolicy
		if strings.HasSuffix(armType, "/resolvers/policies") {
			validate = h.ValidateResolverPolicy
		}
		if validate != nil {
			if err := validate(body.Properties.Value); err != nil {
				writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties.value")
				return
			}
		}
		value, err := h.Store.UpsertPolicy(model.Policy{ScopeID: scopeID, Format: body.Properties.Format, Value: body.Properties.Value})
		if err != nil {
			h.storeError(w, err, scopeID)
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), scopeID)
			return
		}
		writeResource(w, http.StatusCreated, policyWire(scopeID, armType, value), value.ETag)
	default:
		methodNotAllowed(w)
	}
}

func policyWire(scopeID, armType string, value model.Policy) map[string]any {
	return map[string]any{"id": scopeID + "/policies/policy", "name": "policy", "type": armType, "properties": map[string]any{"format": value.Format, "value": value.Value}}
}
