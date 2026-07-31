// Package arm implements the Microsoft.ApiManagement management surface.
package arm

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/calvinchengx/azure-apim-emulator/internal/auth"
	certutil "github.com/calvinchengx/azure-apim-emulator/internal/certificate"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	openapic "github.com/calvinchengx/azure-apim-emulator/internal/openapi"
	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

var supportedVersions = map[string]bool{"2021-08-01": true, "2022-08-01": true, "2024-05-01": true}
var namedValueDisplayName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// Handler serves the P0 APIM ARM resources.
type Handler struct {
	Store          *store.Store
	Auth           auth.RequestValidator
	Activate       func() error
	ValidatePolicy func(string) error
	ImportClient   *http.Client
	ExportKey      []byte
	mutationMu     sync.Mutex
}

// ServeHTTP routes APIM provider requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := store.NewOpaqueID()
	w.Header().Set("x-ms-request-id", requestID)
	w.Header().Set("x-ms-correlation-request-id", requestID)
	if r.URL.Query().Get("export") == "download" {
		h.apiExportDownload(w, r)
		return
	}
	if _, err := h.Auth.ValidateRequest(r); err != nil {
		writeError(w, http.StatusUnauthorized, "AuthenticationFailed", err.Error(), "")
		return
	}
	version := r.URL.Query().Get("api-version")
	if !supportedVersions[version] {
		writeError(w, http.StatusBadRequest, "InvalidApiVersionParameter", "The api-version query parameter is invalid or unsupported.", "api-version")
		return
	}
	parsed, ok := parse(split(r.URL.Path))
	if !ok {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested resource was not found.", r.URL.Path)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
		h.mutationMu.Lock()
		defer h.mutationMu.Unlock()
	}
	if h.handleConditionalRequest(w, r, parsed) {
		return
	}
	h.routeRequest(w, r, parsed)
}

func (h *Handler) routeRequest(w http.ResponseWriter, r *http.Request, parsed route) {
	if h.handleCollectionRequest(w, r, parsed) {
		return
	}
	h.dispatch(w, r, parsed)
}

func (h *Handler) dispatch(w http.ResponseWriter, r *http.Request, parsed route) {
	if len(parsed.Tail) == 0 {
		h.service(w, r, parsed)
		return
	}
	switch parsed.Tail[0] {
	case "apis":
		h.api(w, r, parsed)
	case "apiVersionSets":
		h.apiVersionSet(w, r, parsed)
	case "namedValues":
		h.namedValue(w, r, parsed)
	case "backends":
		h.backend(w, r, parsed)
	case "certificates":
		h.certificate(w, r, parsed)
	case "tags":
		h.tag(w, r, parsed)
	case "groups":
		h.group(w, r, parsed)
	case "users":
		h.user(w, r, parsed)
	case "policyFragments":
		h.policyFragment(w, r, parsed)
	case "loggers":
		h.logger(w, r, parsed)
	case "diagnostics":
		h.diagnostic(w, r, parsed, model.Service{SubscriptionID: parsed.SubscriptionID, ResourceGroup: parsed.ResourceGroup, Name: parsed.ServiceName}.ID(), 1)
	case "products":
		h.product(w, r, parsed)
	case "subscriptions":
		h.subscription(w, r, parsed)
	default:
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested APIM resource is not implemented in the P0 surface.", r.URL.Path)
	}
}

type route struct {
	SubscriptionID, ResourceGroup, ServiceName string
	Tail                                       []string
}

type servicePayload struct {
	Location string `json:"location"`
	SKU      struct {
		Name     string `json:"name"`
		Capacity int    `json:"capacity"`
	} `json:"sku"`
	Properties struct {
		PublisherName  string `json:"publisherName"`
		PublisherEmail string `json:"publisherEmail"`
	} `json:"properties"`
}

func parse(parts []string) (route, bool) {
	if len(parts) >= 5 && equal(parts[0], "subscriptions") && equal(parts[2], "providers") &&
		equal(parts[3], "Microsoft.ApiManagement") && equal(parts[4], "service") {
		result := route{SubscriptionID: parts[1]}
		if len(parts) > 5 {
			result.ServiceName, result.Tail = parts[5], parts[6:]
		}
		return result, true
	}
	if len(parts) >= 7 && equal(parts[0], "subscriptions") && equal(parts[2], "resourceGroups") &&
		equal(parts[4], "providers") && equal(parts[5], "Microsoft.ApiManagement") && equal(parts[6], "service") {
		result := route{SubscriptionID: parts[1], ResourceGroup: parts[3]}
		if len(parts) > 7 {
			result.ServiceName, result.Tail = parts[7], parts[8:]
		}
		return result, true
	}
	return route{}, false
}

func (h *Handler) service(w http.ResponseWriter, r *http.Request, rt route) {
	if rt.ServiceName == "" {
		h.listServices(w, r, rt)
		return
	}
	value := model.Service{SubscriptionID: rt.SubscriptionID, ResourceGroup: rt.ResourceGroup, Name: rt.ServiceName}
	switch r.Method {
	case http.MethodGet:
		got, err := h.Store.GetService(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		writeResource(w, http.StatusOK, serviceWire(got), got.ETag)
	case http.MethodPut:
		var body servicePayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if body.Location == "" || body.Properties.PublisherName == "" || body.Properties.PublisherEmail == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "location, properties.publisherName, and properties.publisherEmail are required.", "properties")
			return
		}
		_, existingErr := h.Store.GetService(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		value.Location, value.SKUName, value.SKUCapacity = body.Location, body.SKU.Name, body.SKU.Capacity
		value.PublisherName, value.PublisherEmail, value.Document = body.Properties.PublisherName, body.Properties.PublisherEmail, document
		if value.SKUName == "" {
			value.SKUName = "Developer"
		}
		if value.SKUCapacity == 0 {
			value.SKUCapacity = 1
		}
		got, err := h.Store.UpsertService(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		w.Header().Set("Azure-AsyncOperation", absolute(r, "/_emulator/arm/operations/"+store.NewOpaqueID()+"?api-version="+r.URL.Query().Get("api-version")))
		status := http.StatusCreated
		if existingErr == nil {
			status = http.StatusOK
		}
		writeResource(w, status, serviceWire(got), got.ETag)
	case http.MethodPatch:
		got, err := h.Store.GetService(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		var body struct {
			Location string `json:"location"`
			SKU      struct {
				Name     *string `json:"name"`
				Capacity *int    `json:"capacity"`
			} `json:"sku"`
			Properties struct {
				PublisherName  *string `json:"publisherName"`
				PublisherEmail *string `json:"publisherEmail"`
			} `json:"properties"`
		}
		var patch map[string]any
		if err := decodeDocument(r, &body, &patch); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if got.Document == nil {
			got.Document = serviceWire(got)
		}
		mergeObject(got.Document, patch)
		if body.SKU.Name != nil {
			got.SKUName = *body.SKU.Name
		}
		if body.SKU.Capacity != nil {
			got.SKUCapacity = *body.SKU.Capacity
		}
		if body.Properties.PublisherName != nil {
			got.PublisherName = *body.Properties.PublisherName
		}
		if body.Properties.PublisherEmail != nil {
			got.PublisherEmail = *body.Properties.PublisherEmail
		}
		got, err = h.Store.UpsertService(got)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), value.ID())
			return
		}
		writeResource(w, http.StatusOK, serviceWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteService(value.ID()); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				w.WriteHeader(http.StatusNoContent)
				return
			}
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

func (h *Handler) listServices(w http.ResponseWriter, r *http.Request, rt route) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	services, err := h.Store.ListServices()
	if err != nil {
		h.storeError(w, err, "")
		return
	}
	values := make([]map[string]any, 0)
	for _, service := range services {
		if !equal(service.SubscriptionID, rt.SubscriptionID) || (rt.ResourceGroup != "" && !equal(service.ResourceGroup, rt.ResourceGroup)) {
			continue
		}
		values = append(values, serviceWire(service))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": values})
}

func (h *Handler) api(w http.ResponseWriter, r *http.Request, rt route) {
	service := model.Service{SubscriptionID: rt.SubscriptionID, ResourceGroup: rt.ResourceGroup, Name: rt.ServiceName}
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListAPIs(service.ID())
		if err != nil {
			h.storeError(w, err, service.ID())
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, apiWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources})
		return
	}
	api := model.API{ServiceID: service.ID(), Name: rt.Tail[1]}
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
		values, err := h.Store.ListAPIRevisions(service.ID(), api.Name)
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
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "tags") {
		if _, err := h.Store.GetAPI(api.ID()); err != nil {
			h.storeError(w, err, api.ID())
			return
		}
		h.resourceTag(w, r, service.ID(), api.ID(), rt.Tail[3])
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
		h.resourceTag(w, r, service.ID(), operationID, rt.Tail[5])
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "releases") {
		h.apiReleaseResource(w, r, model.APIRelease{APIID: api.ID(), Name: rt.Tail[3]})
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "policies") && equal(rt.Tail[3], "policy") && r.Method == http.MethodGet {
		value, err := h.Store.GetPolicy(api.ID())
		if err != nil {
			h.storeError(w, err, api.ID())
			return
		}
		writeResource(w, http.StatusOK, policyWire(api.ID(), value), value.ETag)
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "policies") && equal(rt.Tail[3], "policy") && r.Method == http.MethodPut {
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
		if h.ValidatePolicy != nil {
			if err := h.ValidatePolicy(body.Properties.Value); err != nil {
				writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties.value")
				return
			}
		}
		value, err := h.Store.UpsertPolicy(model.Policy{ScopeID: api.ID(), Format: body.Properties.Format, Value: body.Properties.Value})
		if err != nil {
			h.storeError(w, err, api.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), api.ID())
			return
		}
		writeResource(w, http.StatusCreated, policyWire(api.ID(), value), value.ETag)
		return
	}
	writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested API resource was not found.", r.URL.Path)
}

func (h *Handler) tag(w http.ResponseWriter, r *http.Request, rt route) {
	service := model.Service{SubscriptionID: rt.SubscriptionID, ResourceGroup: rt.ResourceGroup, Name: rt.ServiceName}
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListTags(service.ID())
		if err != nil {
			h.storeError(w, err, service.ID())
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, tagWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) != 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested tag resource was not found.", r.URL.Path)
		return
	}
	value := model.Tag{ServiceID: service.ID(), Name: rt.Tail[1]}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetTag(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, tagWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetTag(value.ID())
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
		var body struct {
			Properties struct {
				DisplayName *string `json:"displayName"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = tagWire(value)
			}
			mergeObject(value.Document, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		if body.Properties.DisplayName != nil {
			value.DisplayName = *body.Properties.DisplayName
		}
		if strings.TrimSpace(value.DisplayName) == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "displayName is required.", "properties.displayName")
			return
		}
		got, err := h.Store.UpsertTag(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, tagWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteTag(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) resourceTagCollection(w http.ResponseWriter, r *http.Request, resourceID string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	values, err := h.Store.ListResourceTags(resourceID)
	if err != nil {
		h.storeError(w, err, resourceID)
		return
	}
	resources := make([]map[string]any, 0, len(values))
	for _, value := range values {
		resources = append(resources, tagWire(value))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
}

func (h *Handler) resourceTag(w http.ResponseWriter, r *http.Request, serviceID, resourceID, tagName string) {
	tag := model.Tag{ServiceID: serviceID, Name: tagName}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetResourceTag(resourceID, tag.ID())
		if err != nil {
			h.storeError(w, err, tag.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, tagWire(got), got.ETag)
	case http.MethodPut:
		got, err := h.Store.GetTag(tag.ID())
		if err != nil {
			h.storeError(w, err, tag.ID())
			return
		}
		_, existingErr := h.Store.GetResourceTag(resourceID, tag.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, tag.ID())
			return
		}
		if err := h.Store.AssignTag(resourceID, tag.ID()); err != nil {
			h.storeError(w, err, tag.ID())
			return
		}
		status := http.StatusOK
		if errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, tagWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DetachTag(resourceID, tag.ID()); err != nil {
			h.storeError(w, err, tag.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) group(w http.ResponseWriter, r *http.Request, rt route) {
	service := model.Service{SubscriptionID: rt.SubscriptionID, ResourceGroup: rt.ResourceGroup, Name: rt.ServiceName}
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListGroups(service.ID())
		if err != nil {
			h.storeError(w, err, service.ID())
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, groupWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) >= 3 && equal(rt.Tail[2], "users") {
		group := model.Group{ServiceID: service.ID(), Name: rt.Tail[1]}
		if _, err := h.Store.GetGroup(group.ID()); err != nil {
			h.storeError(w, err, group.ID())
			return
		}
		if len(rt.Tail) == 3 {
			if r.Method != http.MethodGet {
				methodNotAllowed(w)
				return
			}
			values, err := h.Store.ListGroupUsers(group.ID())
			if err != nil {
				h.storeError(w, err, group.ID())
				return
			}
			resources := make([]map[string]any, 0, len(values))
			for _, value := range values {
				resources = append(resources, userWire(value))
			}
			writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
			return
		}
		if len(rt.Tail) == 4 {
			h.groupUser(w, r, group, model.User{ServiceID: service.ID(), Name: rt.Tail[3]})
			return
		}
	}
	if len(rt.Tail) != 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested group resource was not found.", r.URL.Path)
		return
	}
	value := model.Group{ServiceID: service.ID(), Name: rt.Tail[1], Type: "custom"}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetGroup(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, groupWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetGroup(value.ID())
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
		var body struct {
			Properties struct {
				DisplayName *string `json:"displayName"`
				Description *string `json:"description"`
				Type        *string `json:"type"`
				ExternalID  *string `json:"externalId"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = groupWire(value)
			}
			mergeObject(value.Document, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		if body.Properties.DisplayName != nil {
			value.DisplayName = *body.Properties.DisplayName
		}
		if body.Properties.Description != nil {
			value.Description = *body.Properties.Description
		}
		if body.Properties.Type != nil {
			value.Type = *body.Properties.Type
		}
		if body.Properties.ExternalID != nil {
			value.ExternalID = *body.Properties.ExternalID
		}
		properties, _ := document["properties"].(map[string]any)
		if field, present := properties["description"]; present && field == nil {
			value.Description = ""
		}
		if field, present := properties["externalId"]; present && field == nil {
			value.ExternalID = ""
		}
		if strings.TrimSpace(value.DisplayName) == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "displayName is required.", "properties.displayName")
			return
		}
		if value.Type != "custom" && value.Type != "external" && value.Type != "system" {
			writeError(w, http.StatusBadRequest, "ValidationError", "type must be custom, external, or system.", "properties.type")
			return
		}
		if value.Type == "system" && !value.BuiltIn {
			writeError(w, http.StatusBadRequest, "ValidationError", "system groups are managed by the service.", "properties.type")
			return
		}
		if value.Type == "external" && strings.TrimSpace(value.ExternalID) == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "externalId is required for external groups.", "properties.externalId")
			return
		}
		got, err := h.Store.UpsertGroup(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, groupWire(got), got.ETag)
	case http.MethodDelete:
		got, err := h.Store.GetGroup(value.ID())
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		if err == nil && got.BuiltIn {
			writeError(w, http.StatusBadRequest, "ValidationError", "Built-in groups cannot be deleted.", value.ID())
			return
		}
		if err := h.Store.DeleteGroup(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) groupUser(w http.ResponseWriter, r *http.Request, group model.Group, user model.User) {
	if _, err := h.Store.GetUser(user.ID()); err != nil {
		h.storeError(w, err, user.ID())
		return
	}
	exists, err := h.Store.HasGroupUser(group.ID(), user.ID())
	if err != nil {
		h.storeError(w, err, user.ID())
		return
	}
	switch r.Method {
	case http.MethodHead:
		if !exists {
			h.storeError(w, store.ErrNotFound, user.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPut:
		if err := h.Store.LinkGroupUser(group.ID(), user.ID()); err != nil {
			h.storeError(w, err, user.ID())
			return
		}
		status := http.StatusCreated
		if exists {
			status = http.StatusOK
		}
		got, _ := h.Store.GetUser(user.ID())
		writeResource(w, status, userWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.UnlinkGroupUser(group.ID(), user.ID()); err != nil {
			h.storeError(w, err, user.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) user(w http.ResponseWriter, r *http.Request, rt route) {
	service := model.Service{SubscriptionID: rt.SubscriptionID, ResourceGroup: rt.ResourceGroup, Name: rt.ServiceName}
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListUsers(service.ID())
		if err != nil {
			h.storeError(w, err, service.ID())
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, userWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	value := model.User{ServiceID: service.ID(), Name: rt.Tail[1], State: "active"}
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
		if err := decode(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
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

func (h *Handler) policyFragment(w http.ResponseWriter, r *http.Request, rt route) {
	service := model.Service{SubscriptionID: rt.SubscriptionID, ResourceGroup: rt.ResourceGroup, Name: rt.ServiceName}
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListPolicyFragments(service.ID())
		if err != nil {
			h.storeError(w, err, service.ID())
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, policyFragmentWire(value, r.URL.Query().Get("format")))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	value := model.PolicyFragment{ServiceID: service.ID(), Name: rt.Tail[1], Format: "xml", ProvisioningState: "Succeeded"}
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
		references, err := h.Store.ListPolicyFragmentReferences(service.ID(), value.Name)
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
		references, err := h.Store.ListPolicyFragmentReferences(service.ID(), value.Name)
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
		if err := decode(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if _, _, err := mime.ParseMediaType(body.Properties.ContentType); err != nil || !strings.Contains(body.Properties.ContentType, "/") {
			writeError(w, http.StatusBadRequest, "ValidationError", "properties.contentType must be a valid media type.", "properties.contentType")
			return
		}
		value.ContentType, value.Document = body.Properties.ContentType, body.Properties.Document
		got, err := h.Store.UpsertAPISchema(value)
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		status := http.StatusOK
		if errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, apiSchemaWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteAPISchema(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
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
		if api.DisplayName == "" || api.ServiceURL == "" {
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

const maxImportBytes = 4 << 20

func (h *Handler) resolveImport(r *http.Request, format, value string) (string, string, error) {
	linked := format == "openapi-link" || format == "openapi+json-link" || format == "swagger-link-json"
	if !linked {
		if format != "openapi" && format != "openapi+json" && format != "swagger-json" {
			return "", "", fmt.Errorf("unsupported import format %q", format)
		}
		if len(value) > maxImportBytes {
			return "", "", errors.New("API definition exceeds the 4 MiB import limit")
		}
		return value, "", nil
	}
	sourceURL, err := url.Parse(value)
	if err != nil || (sourceURL.Scheme != "http" && sourceURL.Scheme != "https") || sourceURL.Host == "" {
		return "", "", errors.New("linked API definition must be an absolute HTTP or HTTPS URL")
	}
	client := h.ImportClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	request, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, sourceURL.String(), nil)
	response, err := client.Do(request)
	if err != nil {
		return "", "", fmt.Errorf("retrieve linked API definition: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("linked API definition returned HTTP %d", response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maxImportBytes+1))
	if err != nil {
		return "", "", fmt.Errorf("read linked API definition: %w", err)
	}
	if len(content) > maxImportBytes {
		return "", "", errors.New("API definition exceeds the 4 MiB import limit")
	}
	return string(content), sourceURL.String(), nil
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

func (h *Handler) renderAPIExport(api model.API, format string) ([]byte, string, string, error) {
	operations, err := h.Store.ListOperations(api.ID())
	if err != nil {
		return nil, "", "", err
	}
	schemas, err := h.Store.ListAPISchemas(api.ID())
	if err != nil {
		return nil, "", "", err
	}
	definitions := map[string]any{}
	for _, schema := range schemas {
		if schema.Name != "openapi" {
			continue
		}
		if values, ok := schema.Document["components"].(map[string]any); ok {
			definitions = values
		}
		if values, ok := schema.Document["definitions"].(map[string]any); ok {
			definitions = values
		}
	}
	return openapic.Export(api, operations, definitions, format)
}

func (h *Handler) exportSignature(apiID, format string, expires int64) string {
	key := h.ExportKey
	if len(key) == 0 {
		key = []byte("azure-apim-emulator-local-export")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = fmt.Fprintf(mac, "%s\n%s\n%d", strings.ToLower(apiID), format, expires)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (h *Handler) revisionSource(id string) (model.API, string, error) {
	value, err := h.Store.GetAPI(id)
	if errors.Is(err, store.ErrNotFound) && strings.HasSuffix(strings.ToLower(id), ";rev=1") {
		id = id[:len(id)-6]
		value, err = h.Store.GetAPI(id)
	}
	return value, id, err
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

func (h *Handler) apiVersionSet(w http.ResponseWriter, r *http.Request, rt route) {
	service := model.Service{SubscriptionID: rt.SubscriptionID, ResourceGroup: rt.ResourceGroup, Name: rt.ServiceName}
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListAPIVersionSets(service.ID())
		if err != nil {
			h.storeError(w, err, service.ID())
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, apiVersionSetWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) != 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested API version set resource was not found.", r.URL.Path)
		return
	}
	value := model.APIVersionSet{ServiceID: service.ID(), Name: rt.Tail[1]}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetAPIVersionSet(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, apiVersionSetWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetAPIVersionSet(value.ID())
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
		var body struct {
			Properties struct {
				DisplayName       *string `json:"displayName"`
				VersioningScheme  *string `json:"versioningScheme"`
				VersionHeaderName *string `json:"versionHeaderName"`
				VersionQueryName  *string `json:"versionQueryName"`
				Description       *string `json:"description"`
			} `json:"properties"`
		}
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if value.Document == nil {
				value.Document = apiVersionSetWire(value)
			}
			mergeObject(value.Document, document)
		} else {
			value.Document = document
		}
		cleanResourceDocument(value.Document)
		if body.Properties.DisplayName != nil {
			value.DisplayName = *body.Properties.DisplayName
		}
		if body.Properties.VersioningScheme != nil {
			value.VersioningScheme = *body.Properties.VersioningScheme
		}
		if body.Properties.VersionHeaderName != nil {
			value.VersionHeaderName = *body.Properties.VersionHeaderName
		}
		if body.Properties.VersionQueryName != nil {
			value.VersionQueryName = *body.Properties.VersionQueryName
		}
		if body.Properties.Description != nil {
			value.Description = *body.Properties.Description
		}
		properties, _ := document["properties"].(map[string]any)
		if field, present := properties["versionHeaderName"]; present && field == nil {
			value.VersionHeaderName = ""
		}
		if field, present := properties["versionQueryName"]; present && field == nil {
			value.VersionQueryName = ""
		}
		if field, present := properties["description"]; present && field == nil {
			value.Description = ""
		}
		if err := validateAPIVersionSet(value); err != nil {
			writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties")
			return
		}
		got, err := h.Store.UpsertAPIVersionSet(value)
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
		writeResource(w, status, apiVersionSetWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteAPIVersionSet(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
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

func validateAPIVersionSet(value model.APIVersionSet) error {
	if value.DisplayName == "" || (value.VersioningScheme != "Segment" && value.VersioningScheme != "Header" && value.VersioningScheme != "Query") {
		return errors.New("displayName and a valid versioningScheme are required")
	}
	if value.VersioningScheme == "Header" && value.VersionHeaderName == "" {
		return errors.New("versionHeaderName is required for Header versioning")
	}
	if value.VersioningScheme == "Query" && value.VersionQueryName == "" {
		return errors.New("versionQueryName is required for Query versioning")
	}
	return nil
}

type namedValuePayload struct {
	Properties struct {
		DisplayName *string   `json:"displayName"`
		Value       *string   `json:"value"`
		Tags        *[]string `json:"tags"`
		Secret      *bool     `json:"secret"`
		KeyVault    *struct {
			SecretIdentifier *string `json:"secretIdentifier"`
			IdentityClientID *string `json:"identityClientId"`
		} `json:"keyVault"`
	} `json:"properties"`
}

func (h *Handler) namedValue(w http.ResponseWriter, r *http.Request, rt route) {
	service := model.Service{SubscriptionID: rt.SubscriptionID, ResourceGroup: rt.ResourceGroup, Name: rt.ServiceName}
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListNamedValues(service.ID())
		if err != nil {
			h.storeError(w, err, service.ID())
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, namedValueWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) < 2 || len(rt.Tail) > 3 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested named value resource was not found.", r.URL.Path)
		return
	}
	value := model.NamedValue{ServiceID: service.ID(), Name: rt.Tail[1]}
	if len(rt.Tail) == 3 {
		h.namedValueAction(w, r, value, rt.Tail[2])
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetNamedValue(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, namedValueWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetNamedValue(value.ID())
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
		var body namedValuePayload
		if err := decode(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		applyNamedValuePayload(&value, body)
		if value.DisplayName == "" || len(value.DisplayName) > 256 || !namedValueDisplayName.MatchString(value.DisplayName) ||
			(strings.TrimSpace(value.Value) == "" && value.KeyVaultSecretID == "") || len(value.Value) > 4096 {
			writeError(w, http.StatusBadRequest, "ValidationError", "displayName must be a valid named-value identifier and either value or keyVault.secretIdentifier is required.", "properties")
			return
		}
		got, err := h.Store.UpsertNamedValue(value)
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
		writeResource(w, status, namedValueWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteNamedValue(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
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

func (h *Handler) namedValueAction(w http.ResponseWriter, r *http.Request, value model.NamedValue, action string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	got, err := h.Store.GetNamedValue(value.ID())
	if err != nil {
		h.storeError(w, err, value.ID())
		return
	}
	switch action {
	case "listValue":
		writeResource(w, http.StatusOK, map[string]any{"value": got.Value}, got.ETag)
	case "refreshSecret":
		if got.KeyVaultSecretID == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "refreshSecret requires a Key Vault-backed named value.", value.ID())
			return
		}
		writeResource(w, http.StatusOK, namedValueWire(got), got.ETag)
	default:
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested named value action was not found.", r.URL.Path)
	}
}

func applyNamedValuePayload(value *model.NamedValue, body namedValuePayload) {
	if body.Properties.DisplayName != nil {
		value.DisplayName = *body.Properties.DisplayName
	}
	if body.Properties.Value != nil {
		value.Value = *body.Properties.Value
	}
	if body.Properties.Tags != nil {
		value.Tags = *body.Properties.Tags
	}
	if body.Properties.Secret != nil {
		value.Secret = *body.Properties.Secret
	}
	if body.Properties.KeyVault != nil {
		if body.Properties.KeyVault.SecretIdentifier != nil {
			value.KeyVaultSecretID = *body.Properties.KeyVault.SecretIdentifier
		}
		if body.Properties.KeyVault.IdentityClientID != nil {
			value.KeyVaultIdentityID = *body.Properties.KeyVault.IdentityClientID
		}
	}
}

type backendPayload struct {
	Properties struct {
		Title       *string `json:"title"`
		Description *string `json:"description"`
		URL         *string `json:"url"`
		Protocol    *string `json:"protocol"`
		ResourceID  *string `json:"resourceId"`
	} `json:"properties"`
}

func (h *Handler) backend(w http.ResponseWriter, r *http.Request, rt route) {
	service := model.Service{SubscriptionID: rt.SubscriptionID, ResourceGroup: rt.ResourceGroup, Name: rt.ServiceName}
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListBackends(service.ID())
		if err != nil {
			h.storeError(w, err, service.ID())
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, backendWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) < 2 || len(rt.Tail) > 3 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested backend resource was not found.", r.URL.Path)
		return
	}
	value := model.Backend{ServiceID: service.ID(), Name: rt.Tail[1]}
	if len(rt.Tail) == 3 {
		if rt.Tail[2] != "reconnect" {
			writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested backend action was not found.", r.URL.Path)
			return
		}
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		got, err := h.Store.GetBackend(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		w.Header().Set("ETag", got.ETag)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetBackend(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, backendWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetBackend(value.ID())
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
		var body backendPayload
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
		applyBackendPayload(&value, body)
		parsedURL, urlErr := url.ParseRequestURI(value.URL)
		if value.URL == "" || urlErr != nil || parsedURL.Scheme == "" || parsedURL.Host == "" || (value.Protocol != "http" && value.Protocol != "soap") {
			writeError(w, http.StatusBadRequest, "ValidationError", "properties.url and a valid properties.protocol are required.", "properties")
			return
		}
		got, err := h.Store.UpsertBackend(value)
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
		writeResource(w, status, backendWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteBackend(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
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

func applyBackendPayload(value *model.Backend, body backendPayload) {
	if body.Properties.Title != nil {
		value.Title = *body.Properties.Title
	}
	if body.Properties.Description != nil {
		value.Description = *body.Properties.Description
	}
	if body.Properties.URL != nil {
		value.URL = *body.Properties.URL
	}
	if body.Properties.Protocol != nil {
		value.Protocol = *body.Properties.Protocol
	}
	if body.Properties.ResourceID != nil {
		value.ResourceID = *body.Properties.ResourceID
	}
}

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
	service := model.Service{SubscriptionID: rt.SubscriptionID, ResourceGroup: rt.ResourceGroup, Name: rt.ServiceName}
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListLoggers(service.ID())
		if err != nil {
			h.storeError(w, err, service.ID())
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
	value := model.Logger{ServiceID: service.ID(), Name: rt.Tail[1], IsBuffered: true}
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
		} else {
			value.Document = document
		}
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

type certificatePayload struct {
	Properties struct {
		Data     []byte  `json:"data"`
		Password *string `json:"password"`
		KeyVault *struct {
			SecretIdentifier *string `json:"secretIdentifier"`
			IdentityClientID *string `json:"identityClientId"`
		} `json:"keyVault"`
	} `json:"properties"`
}

func (h *Handler) certificate(w http.ResponseWriter, r *http.Request, rt route) {
	service := model.Service{SubscriptionID: rt.SubscriptionID, ResourceGroup: rt.ResourceGroup, Name: rt.ServiceName}
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListCertificates(service.ID())
		if err != nil {
			h.storeError(w, err, service.ID())
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, certificateWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) < 2 || len(rt.Tail) > 3 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested certificate resource was not found.", r.URL.Path)
		return
	}
	value := model.Certificate{ServiceID: service.ID(), Name: rt.Tail[1]}
	if len(rt.Tail) == 3 {
		if rt.Tail[2] != "refreshSecret" {
			writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested certificate action was not found.", r.URL.Path)
			return
		}
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		got, err := h.Store.GetCertificate(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if got.KeyVaultSecretID == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "refreshSecret requires a Key Vault-backed certificate.", value.ID())
			return
		}
		writeResource(w, http.StatusOK, certificateWire(got), got.ETag)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetCertificate(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, certificateWire(got), got.ETag)
	case http.MethodPut:
		_, existingErr := h.Store.GetCertificate(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		var body certificatePayload
		if err := decode(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if body.Properties.Password != nil {
			value.Password = *body.Properties.Password
		}
		if body.Properties.KeyVault != nil {
			if body.Properties.KeyVault.SecretIdentifier != nil {
				value.KeyVaultSecretID = *body.Properties.KeyVault.SecretIdentifier
			}
			if body.Properties.KeyVault.IdentityClientID != nil {
				value.KeyVaultIdentityID = *body.Properties.KeyVault.IdentityClientID
			}
		}
		value.Data = body.Properties.Data
		if (len(value.Data) == 0) == (value.KeyVaultSecretID == "") {
			writeError(w, http.StatusBadRequest, "ValidationError", "exactly one of data or keyVault.secretIdentifier is required.", "properties")
			return
		}
		if len(value.Data) != 0 {
			leaf, thumbprint, err := certutil.ParsePKCS12(value.Data, value.Password)
			if err != nil {
				writeError(w, http.StatusBadRequest, "ValidationError", err.Error(), "properties.data")
				return
			}
			value.Subject, value.Thumbprint, value.Expiration = leaf.Subject.String(), thumbprint, leaf.NotAfter.UTC()
		}
		got, err := h.Store.UpsertCertificate(value)
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
		writeResource(w, status, certificateWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteCertificate(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
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

func cleanResourceDocument(document map[string]any) {
	delete(document, "id")
	delete(document, "name")
	delete(document, "type")
	delete(document, "etag")
}

func (h *Handler) product(w http.ResponseWriter, r *http.Request, rt route) {
	service := model.Service{SubscriptionID: rt.SubscriptionID, ResourceGroup: rt.ResourceGroup, Name: rt.ServiceName}
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListProducts(service.ID())
		if err != nil {
			h.storeError(w, err, service.ID())
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, productWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources})
		return
	}
	product := model.Product{ServiceID: service.ID(), Name: rt.Tail[1]}
	if len(rt.Tail) == 2 {
		h.productResource(w, r, product)
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "apis") {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		ids, err := h.Store.ListProductAPIs(product.ID())
		if err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		resources := make([]map[string]any, 0, len(ids))
		for _, id := range ids {
			api, err := h.Store.GetAPI(id)
			if err != nil {
				h.storeError(w, err, id)
				return
			}
			resources = append(resources, apiWire(api))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources})
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "tags") {
		if _, err := h.Store.GetProduct(product.ID()); err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		h.resourceTagCollection(w, r, product.ID())
		return
	}
	if len(rt.Tail) == 3 && equal(rt.Tail[2], "groups") {
		if _, err := h.Store.GetProduct(product.ID()); err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListProductGroups(product.ID())
		if err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, groupWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "apis") {
		apiID := service.ID() + "/apis/" + rt.Tail[3]
		switch r.Method {
		case http.MethodPut:
			if err := h.Store.LinkProductAPI(product.ID(), apiID); err != nil {
				h.storeError(w, err, product.ID())
				return
			}
			if err := h.activate(); err != nil {
				writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), product.ID())
				return
			}
			writeResource(w, http.StatusCreated, productAPIWire(product.ID(), rt.Tail[3]), "")
		case http.MethodDelete:
			if err := h.Store.UnlinkProductAPI(product.ID(), apiID); err != nil && !errors.Is(err, store.ErrNotFound) {
				h.storeError(w, err, product.ID())
				return
			}
			if err := h.activate(); err != nil {
				writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), product.ID())
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w)
		}
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "tags") {
		if _, err := h.Store.GetProduct(product.ID()); err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		h.resourceTag(w, r, service.ID(), product.ID(), rt.Tail[3])
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "groups") {
		if _, err := h.Store.GetProduct(product.ID()); err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		group := model.Group{ServiceID: service.ID(), Name: rt.Tail[3]}
		got, err := h.Store.GetGroup(group.ID())
		if err != nil {
			h.storeError(w, err, group.ID())
			return
		}
		exists, err := h.Store.HasProductGroup(product.ID(), group.ID())
		if err != nil {
			h.storeError(w, err, group.ID())
			return
		}
		switch r.Method {
		case http.MethodGet:
			if !exists {
				h.storeError(w, store.ErrNotFound, group.ID())
				return
			}
			writeResource(w, http.StatusOK, groupWire(got), got.ETag)
		case http.MethodHead:
			if !exists {
				h.storeError(w, store.ErrNotFound, group.ID())
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodPut:
			if err := h.Store.LinkProductGroup(product.ID(), group.ID()); err != nil {
				h.storeError(w, err, group.ID())
				return
			}
			status := http.StatusCreated
			if exists {
				status = http.StatusOK
			}
			writeResource(w, status, groupWire(got), got.ETag)
		case http.MethodDelete:
			if err := h.Store.UnlinkProductGroup(product.ID(), group.ID()); err != nil {
				h.storeError(w, err, group.ID())
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w)
		}
		return
	}
	writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested product resource was not found.", r.URL.Path)
}

type productPayload struct {
	Properties struct {
		DisplayName      *string `json:"displayName"`
		State            *string `json:"state"`
		ApprovalRequired *bool   `json:"approvalRequired"`
	} `json:"properties"`
}

func (h *Handler) productResource(w http.ResponseWriter, r *http.Request, product model.Product) {
	switch r.Method {
	case http.MethodGet:
		got, err := h.Store.GetProduct(product.ID())
		if err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		writeResource(w, http.StatusOK, productWire(got), got.ETag)
	case http.MethodPut, http.MethodPatch:
		existing, existingErr := h.Store.GetProduct(product.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, product.ID())
			return
		}
		if r.Method == http.MethodPatch {
			if existingErr != nil {
				h.storeError(w, existingErr, product.ID())
				return
			}
			product = existing
		} else {
			product.State = "notPublished"
		}
		var body productPayload
		var document map[string]any
		if err := decodeDocument(r, &body, &document); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		if r.Method == http.MethodPatch {
			if product.Document == nil {
				product.Document = productWire(product)
			}
			mergeObject(product.Document, document)
		} else {
			product.Document = document
		}
		cleanResourceDocument(product.Document)
		applyProductPayload(&product, body)
		if product.DisplayName == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "displayName is required.", "properties.displayName")
			return
		}
		got, err := h.Store.UpsertProduct(product)
		if err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), product.ID())
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPut && errors.Is(existingErr, store.ErrNotFound) {
			status = http.StatusCreated
		}
		writeResource(w, status, productWire(got), got.ETag)
	case http.MethodDelete:
		if err := h.Store.DeleteProduct(product.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, product.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), product.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func applyProductPayload(product *model.Product, body productPayload) {
	if body.Properties.DisplayName != nil {
		product.DisplayName = *body.Properties.DisplayName
	}
	if body.Properties.State != nil {
		product.State = *body.Properties.State
	}
	if body.Properties.ApprovalRequired != nil {
		product.ApprovalRequired = *body.Properties.ApprovalRequired
	}
}

func (h *Handler) subscription(w http.ResponseWriter, r *http.Request, rt route) {
	service := model.Service{SubscriptionID: rt.SubscriptionID, ResourceGroup: rt.ResourceGroup, Name: rt.ServiceName}
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListSubscriptions(service.ID())
		if err != nil {
			h.storeError(w, err, service.ID())
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, subscriptionWire(value, false))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources})
		return
	}
	value := model.Subscription{ServiceID: service.ID(), Name: rt.Tail[1]}
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
		if err := decode(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		applySubscriptionPayload(&value, body)
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

func (h *Handler) activate() error {
	if h.Activate == nil {
		return nil
	}
	return h.Activate()
}
func (h *Handler) storeError(w http.ResponseWriter, err error, target string) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The resource was not found.", target)
	} else {
		writeError(w, http.StatusConflict, "Conflict", err.Error(), target)
	}
}

// OperationStatus serves deterministic completed LRO polling.
func OperationStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "Succeeded"})
}

func serviceWire(v model.Service) map[string]any {
	result := cloneObject(v.Document)
	result["id"] = v.ID()
	result["name"] = v.Name
	result["type"] = "Microsoft.ApiManagement/service"
	result["location"] = v.Location
	result["etag"] = v.ETag
	result["sku"] = map[string]any{"name": v.SKUName, "capacity": v.SKUCapacity}
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["publisherName"] = v.PublisherName
	properties["publisherEmail"] = v.PublisherEmail
	properties["provisioningState"] = v.ProvisioningState
	properties["gatewayUrl"] = "https://" + v.Name + ".azure-api.localhost"
	properties["gatewayRegionalUrl"] = "https://" + v.Name + ".azure-api.localhost"
	properties["developerPortalUrl"] = "https://" + v.Name + ".portal.azure-api.localhost"
	properties["portalUrl"] = "https://" + v.Name + ".portal.azure-api.localhost"
	properties["managementApiUrl"] = "https://" + v.Name + ".management.azure-api.localhost"
	properties["scmUrl"] = "https://" + v.Name + ".scm.azure-api.localhost"
	return result
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
func apiVersionSetWire(v model.APIVersionSet) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/apiVersionSets"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["displayName"], properties["versioningScheme"] = v.DisplayName, v.VersioningScheme
	properties["versionHeaderName"], properties["versionQueryName"] = v.VersionHeaderName, v.VersionQueryName
	properties["description"] = v.Description
	return result
}
func namedValueWire(v model.NamedValue) map[string]any {
	properties := map[string]any{"displayName": v.DisplayName, "secret": v.Secret, "tags": v.Tags}
	if v.KeyVaultSecretID != "" {
		properties["keyVault"] = map[string]any{"secretIdentifier": v.KeyVaultSecretID, "identityClientId": v.KeyVaultIdentityID}
	}
	return map[string]any{"id": v.ID(), "name": v.Name, "type": "Microsoft.ApiManagement/service/namedValues", "properties": properties}
}
func backendWire(v model.Backend) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/backends"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["title"], properties["description"], properties["url"] = v.Title, v.Description, v.URL
	properties["protocol"], properties["resourceId"] = v.Protocol, v.ResourceID
	return result
}
func certificateWire(v model.Certificate) map[string]any {
	properties := map[string]any{}
	if v.Subject != "" {
		properties["subject"] = v.Subject
	}
	if v.Thumbprint != "" {
		properties["thumbprint"] = v.Thumbprint
	}
	if !v.Expiration.IsZero() {
		properties["expirationDate"] = v.Expiration.UTC().Format(time.RFC3339)
	}
	if v.KeyVaultSecretID != "" {
		properties["keyVault"] = map[string]any{"secretIdentifier": v.KeyVaultSecretID, "identityClientId": v.KeyVaultIdentityID}
	}
	return map[string]any{"id": v.ID(), "name": v.Name, "type": "Microsoft.ApiManagement/service/certificates", "properties": properties}
}
func apiRevisionWire(v model.API) map[string]any {
	base, _ := splitAPIRevision(v.Name)
	apiID := model.API{ServiceID: v.ServiceID, Name: base + ";rev=" + v.Revision}.ID()
	return map[string]any{"apiId": apiID, "apiRevision": v.Revision, "description": v.RevisionDescription,
		"createdDateTime": time.Unix(v.CreatedAt, 0).UTC().Format(time.RFC3339),
		"updatedDateTime": time.Unix(v.UpdatedAt, 0).UTC().Format(time.RFC3339), "isOnline": true, "isCurrent": v.IsCurrent}
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
func apiSchemaWire(v model.APISchema) map[string]any {
	return map[string]any{"id": v.ID(), "name": v.Name, "type": "Microsoft.ApiManagement/service/apis/schemas", "properties": map[string]any{"contentType": v.ContentType, "document": v.Document}}
}
func tagWire(v model.Tag) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/tags"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["displayName"] = v.DisplayName
	return result
}
func groupWire(v model.Group) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/groups"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["displayName"], properties["description"], properties["type"] = v.DisplayName, v.Description, v.Type
	properties["externalId"], properties["builtIn"] = nullableString(v.ExternalID), v.BuiltIn
	return result
}
func userWire(v model.User) map[string]any {
	identities := make([]map[string]any, 0, len(v.Identities))
	for _, identity := range v.Identities {
		identities = append(identities, map[string]any{"provider": identity.Provider, "id": identity.ID})
	}
	return map[string]any{"id": v.ID(), "name": v.Name, "type": "Microsoft.ApiManagement/service/users", "properties": map[string]any{"firstName": v.FirstName, "lastName": v.LastName, "email": v.Email, "state": v.State, "note": v.Note, "identities": identities, "registrationDate": time.Unix(v.RegistrationAt, 0).UTC().Format(time.RFC3339)}}
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
func loggerWire(v model.Logger) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/loggers"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["loggerType"], properties["description"] = v.LoggerType, v.Description
	properties["isBuffered"], properties["resourceId"], properties["credentials"] = v.IsBuffered, v.ResourceID, v.Credentials
	return result
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
func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
func productWire(v model.Product) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"], result["type"] = v.ID(), v.Name, "Microsoft.ApiManagement/service/products"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	properties["displayName"], properties["state"], properties["approvalRequired"] = v.DisplayName, v.State, v.ApprovalRequired
	if _, present := properties["subscriptionRequired"]; !present {
		properties["subscriptionRequired"] = true
	}
	return result
}
func productAPIWire(productID, apiName string) map[string]any {
	return map[string]any{"id": productID + "/apis/" + apiName, "name": apiName, "type": "Microsoft.ApiManagement/service/products/apis"}
}
func subscriptionWire(v model.Subscription, secrets bool) map[string]any {
	properties := map[string]any{"displayName": v.DisplayName, "scope": v.Scope, "state": v.State}
	if secrets {
		properties["primaryKey"], properties["secondaryKey"] = v.PrimaryKey, v.SecondaryKey
	}
	return map[string]any{"id": v.ID(), "name": v.Name, "type": "Microsoft.ApiManagement/service/subscriptions", "properties": properties}
}
func subscriptionSecretsWire(v model.Subscription) map[string]any {
	return map[string]any{"primaryKey": v.PrimaryKey, "secondaryKey": v.SecondaryKey}
}
func policyWire(scopeID string, value model.Policy) map[string]any {
	return map[string]any{"id": scopeID + "/policies/policy", "name": "policy", "type": "Microsoft.ApiManagement/service/apis/policies", "properties": map[string]any{"format": value.Format, "value": value.Value}}
}

func decode(r *http.Request, value any) error {
	if err := json.NewDecoder(r.Body).Decode(value); err != nil {
		return fmt.Errorf("malformed request body: %w", err)
	}
	return nil
}
func decodeDocument(r *http.Request, value any, document *map[string]any) error {
	if err := json.NewDecoder(r.Body).Decode(document); err != nil {
		return fmt.Errorf("malformed request body: %w", err)
	}
	encoded, _ := json.Marshal(*document)
	_ = json.Unmarshal(encoded, value)
	return nil
}
func mergeObject(target, patch map[string]any) {
	for key, value := range patch {
		if value == nil {
			delete(target, key)
			continue
		}
		patchObject, patchIsObject := value.(map[string]any)
		targetObject, targetIsObject := target[key].(map[string]any)
		if patchIsObject && targetIsObject {
			mergeObject(targetObject, patchObject)
			continue
		}
		target[key] = value
	}
}
func cloneObject(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		if object, ok := value.(map[string]any); ok {
			result[key] = cloneObject(object)
			continue
		}
		result[key] = value
	}
	return result
}
func writeResource(w http.ResponseWriter, status int, value any, etag string) {
	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	writeJSON(w, status, value)
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, code, message, target string) {
	w.Header().Set("x-ms-error-code", code)
	errorValue := map[string]any{"code": code, "message": message}
	if target != "" {
		errorValue["target"] = target
	}
	writeJSON(w, status, map[string]any{"error": errorValue})
}
func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "The HTTP method is not allowed for this resource.", "")
}
func absolute(r *http.Request, path string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		scheme = forwarded
	}
	return scheme + "://" + r.Host + path
}
func split(path string) []string {
	value := strings.Trim(path, "/")
	if value == "" {
		return nil
	}
	return strings.Split(value, "/")
}
func equal(a, b string) bool { return strings.EqualFold(a, b) }
func splitAPIRevision(name string) (string, string) {
	index := strings.LastIndex(strings.ToLower(name), ";rev=")
	if index < 0 {
		return name, "1"
	}
	return name[:index], name[index+5:]
}
