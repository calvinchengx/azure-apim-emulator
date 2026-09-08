package arm

import (
	"errors"
	"net/http"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

func (h *Handler) product(w http.ResponseWriter, r *http.Request, rt route) {
	scope := rt.scopeID()
	if len(rt.Tail) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		values, err := h.Store.ListProducts(scope)
		if err != nil {
			h.storeError(w, err, scope)
			return
		}
		resources := make([]map[string]any, 0, len(values))
		for _, value := range values {
			resources = append(resources, productWire(value))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources})
		return
	}
	product := model.Product{ServiceID: scope, Name: rt.Tail[1]}
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
	if (len(rt.Tail) == 3 || len(rt.Tail) == 4) && isLinkSegment(rt.Tail[2], "apiLinks", "groupLinks") {
		if _, err := h.Store.GetProduct(product.ID()); err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		surface, err := h.productLinkSurface(product, rt.Tail[2])
		if err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		surface.armType = linkType(rt.Workspace != "", "products", rt.Tail[2])
		name := ""
		if len(rt.Tail) == 4 {
			name = rt.Tail[3]
		}
		h.linkRoute(w, r, surface, name)
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
		apiID := scope + "/apis/" + rt.Tail[3]
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
		h.resourceTag(w, r, scope, product.ID(), rt.Tail[3])
		return
	}
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "groups") {
		if _, err := h.Store.GetProduct(product.ID()); err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		group := model.Group{ServiceID: scope, Name: rt.Tail[3]}
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
	if len(rt.Tail) == 4 && equal(rt.Tail[2], "policies") && equal(rt.Tail[3], "policy") {
		if _, err := h.Store.GetProduct(product.ID()); err != nil {
			h.storeError(w, err, product.ID())
			return
		}
		h.policyResource(w, r, product.ID(), "Microsoft.ApiManagement/service/products/policies")
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
