package arm

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	openapic "github.com/calvinchengx/azure-apim-emulator/internal/openapi"
	soapc "github.com/calvinchengx/azure-apim-emulator/internal/soap"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

func (h *Handler) api(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListAPIs(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, apiWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources})
		return
	}
	api := model.API{ServiceID: scope, Name: rt.Tail[1]}
	if len(rt.Tail) == 2 {
		h.apiResource(w, r, api)
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "operations") {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListOperations(api.ID())
		if err != nil {
			h.storeError(w, err, api.ID())
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, operationWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources})
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "schemas") {
		h.apiSchemaCollection(w, r, api)
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "resolvers") {
		h.apiResolverCollection(w, r, api)
		return
	}
	if len(rt.Tail) >= 3 && equal(rt.Tail[2], "diagnostics") {
		if _, err := h.Store.GetAPI(api.ID()); err != nil {
			h.storeError(w, err, api.ID())
			return
		}
		h.diagnostic(w, r, rt, api.ID(), 3)
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "tags") {
		if _, err := h.Store.GetAPI(api.ID()); err != nil {
			h.storeError(w, err, api.ID())
			return
		}
		h.resourceTagCollection(w, r, api.ID())
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "revisions") {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListAPIRevisions(scope, api.Name)
		if err != nil {
			h.storeError(w, err, api.ID())
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, apiRevisionWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "releases") {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListAPIReleases(api.ID())
		if err != nil {
			h.storeError(w, err, api.ID())
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, apiReleaseWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "operations") {
		h.operationResource(w, r, model.Operation{APIID: api.ID(), Name: rt.Tail[3]})
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "schemas") {
		h.apiSchemaResource(w, r, model.APISchema{APIID: api.ID(), Name: rt.Tail[3]})
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "resolvers") {
		h.apiResolverResource(w, r, model.APIResolver{APIID: api.ID(), Name: rt.Tail[3]})
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "tags") {
		if _, err := h.Store.GetAPI(api.ID()); err != nil {
			h.storeError(w, err, api.ID())
			return
		}
		h.resourceTag(w, r, scope, api.ID(), rt.Tail[3])
		return
	}
	if len(rt.Tail) == 5 && equal(rt.Tail[2], "operations") && equal(rt.Tail[4], "tags") {
		operationID := api.ID() + "/operations/" + rt.Tail[3]
		if _, err := h.Store.GetOperation(operationID); err != nil {
			h.storeError(w, err, operationID)
			return
		}
		h.resourceTagCollection(w, r, operationID)
		return
	}
	if len(rt.Tail) == 6 && equal(rt.Tail[2], "operations") && equal(rt.Tail[4], "tags") {
		operationID := api.ID() + "/operations/" + rt.Tail[3]
		if _, err := h.Store.GetOperation(operationID); err != nil {
			h.storeError(w, err, operationID)
			return
		}
		h.resourceTag(w, r, scope, operationID, rt.Tail[5])
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "releases") {
		h.apiReleaseResource(w, r, model.APIRelease{APIID: api.ID(), Name: rt.Tail[3]})
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "policies") && equal(rt.Tail[3], "policy") {
		h.policyResource(w, r, api.ID(), "Microsoft.ApiManagement/service/apis/policies")
		return
	}
	if len(rt.Tail) == 6 && equal(rt.Tail[2], "resolvers") && equal(rt.Tail[4], "policies") && equal(rt.Tail[5], "policy") {
		resolverID := api.ID() + "/resolvers/" + rt.Tail[3]
		if _, err := h.Store.GetAPIResolver(resolverID); err != nil {
			h.storeError(w, err, resolverID)
			return
		}
		h.policyResource(w, r, resolverID, "Microsoft.ApiManagement/service/apis/resolvers/policies")
		return
	}
	if len(rt.Tail) == 6 && equal(rt.Tail[2], "operations") && equal(rt.Tail[4], "policies") && equal(rt.Tail[5], "policy") {
		operationID := api.ID() + "/operations/" + rt.Tail[3]
		if _, err := h.Store.GetOperation(operationID); err != nil {
			h.storeError(w, err, operationID)
			return
		}
		h.policyResource(w, r, operationID, "Microsoft.ApiManagement/service/apis/operations/policies")
		return
	}
	writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested API resource was not found.", r.URL.Path)
}

type apiPayload struct {
	Properties struct {
		DisplayName            *string   `json:"displayName"`
		Path                   *string   `json:"path"`
		ServiceURL             *string   `json:"serviceUrl"`
		Protocols              *[]string `json:"protocols"`
		SubscriptionRequired   *bool     `json:"subscriptionRequired"`
		APIRevision            *string   `json:"apiRevision"`
		APIRevisionDescription *string   `json:"apiRevisionDescription"`
		IsCurrent              *bool     `json:"isCurrent"`
		SourceAPIID            *string   `json:"sourceApiId"`
		APIVersion             *string   `json:"apiVersion"`
		APIVersionSetID        *string   `json:"apiVersionSetId"`
		Format                 *string   `json:"format"`
		Value                  *string   `json:"value"`
	} `json:"properties"`
}

func (h *Handler) apiResource(w http.ResponseWriter, r *http.Request, api model.API) {
	switch r.Method {
	case http.MethodGet:
		if r.URL.Query().Get("export") == "true" {
			h.apiExport(w, r, api)
			return
		}
		got, err := h.Store.GetAPI(api.ID())
		if err != nil {
			h.storeError(w, err, api.ID())
			return
		}
		writeResource(w, http.StatusOK, apiWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetAPI(api.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, api.ID())
			return
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, api.ID())
				return
			}
			api = existing
		} else {
			api.SubscriptionRequired = true
			api.IsCurrent = !strings.Contains(strings.ToLower(api.Name), ";rev=")
		}
		var body apiPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		cloneSourceID := ""
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) && body.Properties.SourceAPIID != nil {
			targetName := api.Name
			source, sourceID, err := h.revisionSource(*body.Properties.SourceAPIID)
			if err != nil {
				h.storeError(w, err, *body.Properties.SourceAPIID)
				return
			}
			api = source
			api.Name, api.Revision, api.RevisionDescription = targetName, "", ""
			api.IsCurrent, api.CreatedAt, api.UpdatedAt, api.ETag = false, 0, 0, ""
			cloneSourceID = sourceID
		}
		if r.Method == http.MethodPatch || cloneSourceID != "" {
			if api.Document == nil {
				api.Document = apiWire(api)
			}
			mergeObject(api.Document, document)
		} else {
			api.Document = document
		}
		cleanAPIDocument(api.Document)
		applyAPIPayload(&api, body)
		clearNullAPIProperties(&api, document)
		var imported *struct {
			definition model.APIDefinition
			operations []model.Operation
			schema     *model.APISchema
		}
		if body.Properties.Format != nil {
			if r.Method != http.MethodPut || body.Properties.Value == nil {
				writeError(w, http.StatusBadRequest, "ValidationError", "format and value are required for API import.", "properties")
				return
			}
			source, sourceURL, err := h.resolveImport(r, *body.Properties.Format, *body.Properties.Value)
			if err != nil {
				writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties.value")
				return
			}
			// WSDL is a different document with a different parser. Azure
			// imports SOAP through this same format/value pair rather than
			// through a schema sub-resource, so following that shape is what
			// keeps a caller's import script portable.
			if isWSDLFormat(*body.Properties.Format) {
				wsdl, err := soapc.Parse(source)
				if err != nil {
					writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties.value")
					return
				}
				if body.Properties.DisplayName == nil && wsdl.ServiceName != "" {
					api.DisplayName = wsdl.ServiceName
				}
				markSOAPAPIType(api.Document)
				imported = &struct {
					definition model.APIDefinition
					operations []model.Operation
					schema     *model.APISchema
				}{model.APIDefinition{Format: *body.Properties.Format, Value: source, SourceURL: sourceURL}, wsdlOperations(wsdl), nil}
			} else {
				parsed, err := openapic.Parse(source)
				if err != nil {
					writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties.value")
					return
				}
				if body.Properties.DisplayName == nil {
					api.DisplayName = parsed.Title
				}
				if body.Properties.ServiceURL == nil {
					api.ServiceURL = parsed.ServiceURL
				}
				if body.Properties.Protocols == nil && api.ServiceURL != "" {
					protocol := "http"
					if parsedURL, err := url.Parse(api.ServiceURL); err == nil && parsedURL.Scheme == "https" {
						protocol = "https"
					}
					api.Protocols = []string{protocol}
				}
				var schema *model.APISchema
				if len(parsed.Schemas) != 0 {
					contentType, key := "application/vnd.oai.openapi.components+json", "components"
					if parsed.Version == "2.0" {
						contentType, key = "application/vnd.ms-azure-apim.swagger.definitions+json", "definitions"
					}
					schema = &model.APISchema{ContentType: contentType, Document: map[string]any{key: parsed.Schemas}}
				}
				imported = &struct {
					definition model.APIDefinition
					operations []model.Operation
					schema     *model.APISchema
				}{model.APIDefinition{Format: *body.Properties.Format, Value: source, SourceURL: sourceURL}, parsed.Operations, schema}
			}
		}
		// A SYNTHETIC GraphQL API has no backend by definition: its fields come
		// from resolvers, and requiring a serviceUrl would make the shape
		// impossible to create. Pass-through GraphQL still needs one, but that
		// is not knowable here, and the gateway reports a missing backend at
		// request time rather than guessing at import time.
		if api.DisplayName == "" || (api.ServiceURL == "" && !isGraphQLAPIDocument(document)) {
			writeError(w, http.StatusBadRequest, "ValidationError", "displayName and serviceUrl are required.", "properties")
			return
		}
		if (api.Version == "") != (api.VersionSetID == "") {
			writeError(w, http.StatusBadRequest, "ValidationError", "apiVersion and apiVersionSetId must be supplied together.", "properties")
			return
		}
		var got model.API
		var err error
		if imported != nil {
			got, err = h.Store.ImportAPI(api, imported.definition, imported.operations, imported.schema)
		} else if cloneSourceID != "" {
			got, err = h.Store.CloneAPIRevision(cloneSourceID, api)
		} else {
			got, err = h.Store.UpsertAPI(api)
		}
		if err != nil {
			h.storeError(w, err, api.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), api.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, apiWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteAPI(api.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, api.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), api.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) apiExport(w http.ResponseWriter, r *http.Request, api model.API) {
	got, err := h.Store.GetAPI(api.ID())
	if err != nil {
		h.storeError(w, err, api.ID())
		return
	}
	format := r.URL.Query().Get("format")
	_, resultFormat, _, err := h.renderAPIExport(got, format)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "format")
		return
	}
	expires := h.Store.Clock.Now() + 300
	signature := h.exportSignature(got.ID(), format, expires)
	query := url.Values{"api-version": {r.URL.Query().Get("api-version")}, "export": {"download"}, "format": {format}, "expires": {fmt.Sprint(expires)}, "sig": {signature}}
	link := absolute(r, r.URL.Path+"?"+query.Encode())
	writeJSON(w, http.StatusOK, map[string]any{"id": got.ID(), "format": resultFormat, "value": map[string]any{"link": link}})
}

func (h *Handler) apiExportDownload(w http.ResponseWriter, r *http.Request) {
	version := r.URL.Query().Get("api-version")
	parsed, ok := parse(split(r.URL.Path))
	if !supportedVersions[version] || !ok || len(parsed.Tail) != 2 || !equal(parsed.Tail[0], "apis") {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The API export was not found.", r.URL.Path)
		return
	}
	expires, err := strconv.ParseInt(r.URL.Query().Get("expires"), 10, 64)
	api := model.API{ServiceID: model.Service{SubscriptionID: parsed.SubscriptionID, ResourceGroup: parsed.ResourceGroup, Name: parsed.ServiceName}.ID(), Name: parsed.Tail[1]}
	format := r.URL.Query().Get("format")
	if err != nil || !hmac.Equal([]byte(r.URL.Query().Get("sig")), []byte(h.exportSignature(api.ID(), format, expires))) {
		writeError(w, http.StatusForbidden, "AuthorizationFailed", "The API export link is invalid.", "sig")
		return
	}
	if h.Store.Clock.Now() > expires {
		writeError(w, http.StatusGone, "ExportExpired", "The API export link has expired.", "expires")
		return
	}
	got, err := h.Store.GetAPI(api.ID())
	if err != nil {
		h.storeError(w, err, api.ID())
		return
	}
	content, _, contentType, err := h.renderAPIExport(got, format)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "format")
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func applyAPIPayload(api *model.API, body apiPayload) {
	if body.Properties.DisplayName != nil {
		api.DisplayName = *body.Properties.DisplayName
	}
	if body.Properties.Path != nil {
		api.Path = *body.Properties.Path
	}
	if body.Properties.ServiceURL != nil {
		api.ServiceURL = *body.Properties.ServiceURL
	}
	if body.Properties.Protocols != nil {
		api.Protocols = *body.Properties.Protocols
	}
	if body.Properties.SubscriptionRequired != nil {
		api.SubscriptionRequired = *body.Properties.SubscriptionRequired
	}
	if body.Properties.APIRevision != nil {
		api.Revision = *body.Properties.APIRevision
	}
	if body.Properties.APIRevisionDescription != nil {
		api.RevisionDescription = *body.Properties.APIRevisionDescription
	}
	if body.Properties.IsCurrent != nil {
		api.IsCurrent = *body.Properties.IsCurrent
	}
	if body.Properties.APIVersion != nil {
		api.Version = *body.Properties.APIVersion
	}
	if body.Properties.APIVersionSetID != nil {
		api.VersionSetID = *body.Properties.APIVersionSetID
	}
}

func cleanAPIDocument(document map[string]any) {
	cleanResourceDocument(document)
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "format")
	delete(properties, "value")
	delete(properties, "sourceApiId")
}

func clearNullAPIProperties(api *model.API, patch map[string]any) {
	properties, _ := patch["properties"].(map[string]any)
	if value, present := properties["apiRevisionDescription"]; present && value == nil {
		api.RevisionDescription = ""
	}
	if value, present := properties["apiVersion"]; present && value == nil {
		api.Version = ""
	}
	if value, present := properties["apiVersionSetId"]; present && value == nil {
		api.VersionSetID = ""
	}
}

func apiWire(v model.API) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/apis"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	delete(properties, "format")
	delete(properties, "value")
	delete(properties, "sourceApiId")
	properties["displayName"], properties["path"], properties["serviceUrl"] = v.DisplayName, v.Path, v.ServiceURL
	properties["protocols"], properties["subscriptionRequired"] = v.Protocols, v.SubscriptionRequired
	properties["apiRevision"], properties["apiRevisionDescription"], properties["isCurrent"] = v.Revision, v.RevisionDescription, v.IsCurrent
	if v.Version != "" {
		properties["apiVersion"] = v.Version
	} else {
		delete(properties, "apiVersion")
	}
	if v.VersionSetID != "" {
		properties["apiVersionSetId"] = v.VersionSetID
	} else {
		delete(properties, "apiVersionSetId")
	}
	return result
}

func apiRevisionWire(v model.API) map[string]any {
	base, _ := splitAPIRevision(v.Name)
	apiID := model.API{ServiceID: v.ServiceID, Name: base + ";rev=" + v.Revision}.ID()
	return map[string]any{"apiId": apiID, "apiRevision": v.Revision, "description": v.RevisionDescription,
		"createdDateTime": time.Unix(v.CreatedAt, 0).UTC().Format(time.RFC3339),
		"updatedDateTime": time.Unix(v.UpdatedAt, 0).UTC().Format(time.RFC3339), "isOnline": true, "isCurrent": v.IsCurrent}
}
