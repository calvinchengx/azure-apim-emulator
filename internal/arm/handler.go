// Package arm implements the Microsoft.ApiManagement management surface.
package arm

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/auth"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

var supportedVersions = map[string]bool{"2021-08-01": true, "2022-08-01": true, "2024-05-01": true}

// Handler serves the P0 APIM ARM resources.
type Handler struct {
	Store          *store.Store
	Auth           auth.RequestValidator
	Activate       func() error
	ValidatePolicy func(string) error
}

// ServeHTTP routes APIM provider requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := store.NewOpaqueID()
	w.Header().Set("x-ms-request-id", requestID)
	w.Header().Set("x-ms-correlation-request-id", requestID)
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
	if len(parsed.Tail) == 0 {
		h.service(w, r, parsed)
		return
	}
	switch parsed.Tail[0] {
	case "apis":
		h.api(w, r, parsed)
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
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "operations") {
		h.operationResource(w, r, model.Operation{APIID: api.ID(), Name: rt.Tail[3]})
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

type apiPayload struct {
	Properties struct {
		DisplayName          *string   `json:"displayName"`
		Path                 *string   `json:"path"`
		ServiceURL           *string   `json:"serviceUrl"`
		Protocols            *[]string `json:"protocols"`
		SubscriptionRequired *bool     `json:"subscriptionRequired"`
	} `json:"properties"`
}

func (h *Handler) apiResource(w http.ResponseWriter, r *http.Request, api model.API) {
	switch r.Method {
	case http.MethodGet:
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
		}
		var body apiPayload
		if err := decode(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		applyAPIPayload(&api, body)
		if api.DisplayName == "" || api.ServiceURL == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "displayName and serviceUrl are required.", "properties")
			return
		}
		got, err := h.Store.UpsertAPI(api)
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
		if err := decode(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
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
			product.State = "published"
		}
		var body productPayload
		if err := decode(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
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
	if len(rt.Tail) != 2 || r.Method != http.MethodPut {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested subscription resource was not found.", r.URL.Path)
		return
	}
	service := model.Service{SubscriptionID: rt.SubscriptionID, ResourceGroup: rt.ResourceGroup, Name: rt.ServiceName}
	var body struct {
		Properties struct {
			DisplayName  string `json:"displayName"`
			Scope        string `json:"scope"`
			State        string `json:"state"`
			PrimaryKey   string `json:"primaryKey"`
			SecondaryKey string `json:"secondaryKey"`
		} `json:"properties"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
		return
	}
	value := model.Subscription{ServiceID: service.ID(), Name: rt.Tail[1], DisplayName: body.Properties.DisplayName, Scope: body.Properties.Scope, State: body.Properties.State, PrimaryKey: body.Properties.PrimaryKey, SecondaryKey: body.Properties.SecondaryKey}
	got, err := h.Store.UpsertSubscription(value)
	if err != nil {
		h.storeError(w, err, value.ID())
		return
	}
	if err := h.activate(); err != nil {
		writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), value.ID())
		return
	}
	writeResource(w, http.StatusCreated, subscriptionWire(got, false), got.ETag)
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
	return map[string]any{"id": v.ID(), "name": v.Name, "type": "Microsoft.ApiManagement/service/apis", "properties": map[string]any{"displayName": v.DisplayName, "path": v.Path, "serviceUrl": v.ServiceURL, "protocols": v.Protocols, "subscriptionRequired": v.SubscriptionRequired, "apiRevision": "1", "isCurrent": true}}
}
func operationWire(v model.Operation) map[string]any {
	return map[string]any{"id": v.APIID + "/operations/" + v.Name, "name": v.Name, "type": "Microsoft.ApiManagement/service/apis/operations", "properties": map[string]any{"displayName": v.DisplayName, "method": v.Method, "urlTemplate": v.URLTemplate}}
}
func productWire(v model.Product) map[string]any {
	return map[string]any{"id": v.ID(), "name": v.Name, "type": "Microsoft.ApiManagement/service/products", "properties": map[string]any{"displayName": v.DisplayName, "state": v.State, "approvalRequired": v.ApprovalRequired, "subscriptionRequired": true}}
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
