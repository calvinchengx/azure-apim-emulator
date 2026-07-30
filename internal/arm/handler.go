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
		var body struct {
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
		if err := decode(r, &body); err != nil {
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
		value.PublisherName, value.PublisherEmail = body.Properties.PublisherName, body.Properties.PublisherEmail
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
			SKU struct {
				Name     *string `json:"name"`
				Capacity *int    `json:"capacity"`
			} `json:"sku"`
			Properties struct {
				PublisherName  *string `json:"publisherName"`
				PublisherEmail *string `json:"publisherEmail"`
			} `json:"properties"`
		}
		if err := decode(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
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
	if len(rt.Tail) < 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "API identifier is required.", "")
		return
	}
	service := model.Service{SubscriptionID: rt.SubscriptionID, ResourceGroup: rt.ResourceGroup, Name: rt.ServiceName}
	api := model.API{ServiceID: service.ID(), Name: rt.Tail[1]}
	if len(rt.Tail) == 2 && r.Method == http.MethodGet {
		got, err := h.Store.GetAPI(api.ID())
		if err != nil {
			h.storeError(w, err, api.ID())
			return
		}
		writeResource(w, http.StatusOK, apiWire(got), got.ETag)
		return
	}
	if len(rt.Tail) == 2 && r.Method == http.MethodPut {
		var body struct {
			Properties struct {
				DisplayName          string   `json:"displayName"`
				Path                 string   `json:"path"`
				ServiceURL           string   `json:"serviceUrl"`
				Protocols            []string `json:"protocols"`
				SubscriptionRequired *bool    `json:"subscriptionRequired"`
			} `json:"properties"`
		}
		if err := decode(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		api.DisplayName, api.Path, api.ServiceURL, api.Protocols = body.Properties.DisplayName, body.Properties.Path, body.Properties.ServiceURL, body.Properties.Protocols
		api.SubscriptionRequired = true
		if body.Properties.SubscriptionRequired != nil {
			api.SubscriptionRequired = *body.Properties.SubscriptionRequired
		}
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
		writeResource(w, http.StatusCreated, apiWire(got), got.ETag)
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "operations") && r.Method == http.MethodPut {
		var body struct {
			Properties struct {
				DisplayName string `json:"displayName"`
				Method      string `json:"method"`
				URLTemplate string `json:"urlTemplate"`
			} `json:"properties"`
		}
		if err := decode(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		operation := model.Operation{APIID: api.ID(), Name: rt.Tail[3], DisplayName: body.Properties.DisplayName, Method: body.Properties.Method, URLTemplate: body.Properties.URLTemplate}
		got, err := h.Store.UpsertOperation(operation)
		if err != nil {
			h.storeError(w, err, api.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), api.ID())
			return
		}
		writeResource(w, http.StatusCreated, operationWire(got), got.ETag)
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

func (h *Handler) product(w http.ResponseWriter, r *http.Request, rt route) {
	if len(rt.Tail) < 2 {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "Product identifier is required.", "")
		return
	}
	service := model.Service{SubscriptionID: rt.SubscriptionID, ResourceGroup: rt.ResourceGroup, Name: rt.ServiceName}
	product := model.Product{ServiceID: service.ID(), Name: rt.Tail[1]}
	if len(rt.Tail) == 2 && r.Method == http.MethodPut {
		var body struct {
			Properties struct {
				DisplayName      string `json:"displayName"`
				State            string `json:"state"`
				ApprovalRequired bool   `json:"approvalRequired"`
			} `json:"properties"`
		}
		if err := decode(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
			return
		}
		product.DisplayName, product.State, product.ApprovalRequired = body.Properties.DisplayName, body.Properties.State, body.Properties.ApprovalRequired
		if product.State == "" {
			product.State = "published"
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
		writeResource(w, http.StatusCreated, productWire(got), got.ETag)
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "apis") && r.Method == http.MethodPut {
		apiID := service.ID() + "/apis/" + rt.Tail[3]
		if err := h.Store.LinkProductAPI(product.ID(), apiID); err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), product.ID())
			return
		}
		writeResource(w, http.StatusCreated, map[string]any{"id": product.ID() + "/apis/" + rt.Tail[3], "name": rt.Tail[3], "type": "Microsoft.ApiManagement/service/products/apis"}, "")
		return
	}
	writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested product resource was not found.", r.URL.Path)
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
	return map[string]any{"id": v.ID(), "name": v.Name, "type": "Microsoft.ApiManagement/service", "location": v.Location, "etag": v.ETag, "sku": map[string]any{"name": v.SKUName, "capacity": v.SKUCapacity}, "properties": map[string]any{"publisherName": v.PublisherName, "publisherEmail": v.PublisherEmail, "provisioningState": v.ProvisioningState, "gatewayUrl": "https://" + v.Name + ".azure-api.localhost", "developerPortalUrl": "https://" + v.Name + ".portal.azure-api.localhost"}}
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
