package arm

import (
	"errors"
	"mime"
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

func (h *Handler) apiSchemaCollection(w http.ResponseWriter, r *http.Request, api model.API) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	values, err := h.Store.ListAPISchemas(api.ID())
	if err != nil {
		h.storeError(w, err, api.ID())
		return
	}
	resources := make([]map[string]any, 0, len(values))
	for _, value := range values {
		resources = append(resources, apiSchemaWire(value))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
}

func (h *Handler) apiSchemaResource(w http.ResponseWriter, r *http.Request, value model.APISchema) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetAPISchema(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, apiSchemaWire(got), got.ETag)
	case http.MethodPut:
		_, existingErr := h.Store.GetAPISchema(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		var body struct {
			Properties struct {
				ContentType string         `json:"contentType"`
				Document    map[string]any `json:"document"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if _, _, err := mime.ParseMediaType(body.Properties.ContentType); err != nil || !strings.Contains(body.Properties.ContentType, "/") {
			writeError(w, http.StatusBadRequest, "ValidationError", "properties.contentType must be a valid media type.", "properties.contentType")
			return
		}
		value.ContentType, value.Document, value.ARMDocument = body.Properties.ContentType, body.Properties.Document, document
		cleanResourceDocument(value.ARMDocument)
		got, err := h.Store.UpsertAPISchema(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		// A schema is runtime state, not just metadata: a GraphQL schema decides
		// what the gateway will accept. Without republishing here, an imported
		// schema would sit in the store while the gateway kept serving the API
		// as if it had none.
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), value.ID())
			return
		}
		writeResource(w, status, apiSchemaWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteAPISchema(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		// The row is already gone, so this reports a republish failure rather
		// than a rejected request: 500 ConfigurationInvalid, matching every
		// other delete-then-activate path here.
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

// globalSchema serves `/schemas` and `/schemas/{schemaId}`.
//
// THREE THINGS COME FROM MICROSOFT'S CONTRACT RATHER THAN FROM CONVENIENCE,
// read off the generated client types rather than transcribed:
//
//   - `schemaType` is marked **Immutable**, so a PUT that changes it on an
//     existing schema is refused rather than silently accepted. Accepting it
//     is the leniency direction: it works here and fails in a tenant.
//   - `provisioningState` is read-only, server-populated. A caller-supplied
//     value is dropped and the emulator states its own.
//   - CreateOrUpdate is a LONG-RUNNING operation. The SDK exposes it as
//     `beginCreateOrUpdate`, so the response carries Azure-AsyncOperation and a
//     terminal provisioningState; a poller given neither waits forever.
//
// There is no PATCH: the spec declares PUT, GET, HEAD, DELETE and a list, and
// nothing else, so anything else is 405 rather than quietly accepted.
func (h *Handler) globalSchema(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListGlobalSchemas(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, globalSchemaWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) != 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested schema resource was not found.", r.URL.Path)
		return
	}
	if rt.Tail[1] == "" || len(rt.Tail[1]) > 80 {
		writeError(w, http.StatusBadRequest, "ValidationError", "schemaId must be 1-80 characters.", "schemaId")
		return
	}
	value := model.GlobalSchema{ServiceID: scope, Name: rt.Tail[1]}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetGlobalSchema(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, globalSchemaWire(got), got.ETag)
	case http.MethodPut:
		existing, existingErr := h.Store.GetGlobalSchema(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		var body struct {
			Properties struct {
				SchemaType  string         `json:"schemaType"`
				Description string         `json:"description"`
				Value       any            `json:"value"`
				Document    map[string]any `json:"document"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		schemaType := strings.ToLower(strings.TrimSpace(body.Properties.SchemaType))
		if schemaType != "xml" && schemaType != "json" {
			writeError(w, http.StatusBadRequest, "ValidationError", "properties.schemaType must be xml or json.", "properties.schemaType")
			return
		}
		if existingErr == nil && !strings.EqualFold(existing.SchemaType, schemaType) {
			writeError(w, http.StatusBadRequest, "ValidationError",
				"properties.schemaType is immutable and cannot be changed from "+existing.SchemaType+" to "+schemaType+".",
				"properties.schemaType")
			return
		}
		text, _ := body.Properties.Value.(string)
		value.SchemaType, value.Description, value.Value = schemaType, body.Properties.Description, text
		value.Schema, value.Document = body.Properties.Document, document
		cleanResourceDocument(value.Document)
		got, err := h.Store.UpsertGlobalSchema(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		// Long-running in Azure, so the poller is given somewhere to poll and a
		// state it can call terminal.
		w.Header().Set("Azure-AsyncOperation", absolute(r, "/_emulator/arm/operations/"+store.NewOpaqueID()+"?api-version="+r.URL.Query().Get("api-version")))
		status := http.StatusOK
		if errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, globalSchemaWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteGlobalSchema(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func globalSchemaWire(v model.GlobalSchema) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/schemas"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["schemaType"] = v.SchemaType
	properties["description"] = v.Description
	// Exactly one of the two carries the schema, decided by schemaType, so the
	// other is omitted rather than emitted empty. A caller that reads `document`
	// on an xml schema should find nothing there, as in Azure.
	delete(properties, "value")
	delete(properties, "document")
	if v.SchemaType == "json" {
		properties["document"] = v.Schema
	} else {
		properties["value"] = v.Value
	}
	// Server-populated, and stated rather than echoed: the contract marks it
	// read-only, so whatever a caller sent has already been dropped.
	properties["provisioningState"] = "Succeeded"
	return result
}

func apiSchemaWire(v model.APISchema) map[string]any {
	result := cloneObject(v.ARMDocument)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/apis/schemas"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["contentType"], properties["document"] = v.ContentType, v.Document
	return result
}
