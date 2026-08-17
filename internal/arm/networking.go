package arm

import (
	"errors"
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

// Private networking: the connection handshake, the link resources a consumer
// can connect to, and the two read-only status surfaces an operator uses to
// find out whether the service can reach what it depends on.
//
// WHAT THIS CANNOT BE, AND SAYS SO RATHER THAN PRETENDING: a private endpoint
// lives in a consumer's own virtual network and this emulator never reaches one.
// What is faithful here is the MANAGEMENT contract -- the approval state
// machine, the shapes, and the refusals. Reporting a connection as carrying
// traffic would be a success nobody could have observed.

// Connection states, spelled as Azure spells them because a caller compares
// against these strings.
const (
	connectionPending  = "Pending"
	connectionApproved = "Approved"
	connectionRejected = "Rejected"
)

// gatewayGroupID is the only private-link sub-resource an APIM service exposes.
const gatewayGroupID = "Gateway"

// privateEndpointConnectionRoute dispatches the connection resource tree.
func (h *Handler) privateEndpointConnectionRoute(w http.ResponseWriter, r *http.Request, rt route) {
	serviceID := rt.service().ID()
	switch len(rt.Tail) {
	case 1:
		h.privateEndpointConnectionCollection(w, r, serviceID)
	case 2:
		h.privateEndpointConnectionResource(w, r, model.PrivateEndpointConnection{ServiceID: serviceID, Name: rt.Tail[1]})
	default:
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The resource was not found.", serviceID)
	}
}

func (h *Handler) privateEndpointConnectionCollection(w http.ResponseWriter, r *http.Request, serviceID string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	values, err := h.Store.ListPrivateEndpointConnections(serviceID)
	if err != nil {
		h.storeError(w, err, serviceID)
		return
	}
	resources := make([]map[string]any, 0, len(values))
	for _, value := range values {
		resources = append(resources, privateEndpointConnectionWire(value))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
}

func (h *Handler) privateEndpointConnectionResource(w http.ResponseWriter, r *http.Request, value model.PrivateEndpointConnection) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		got, err := h.Store.GetPrivateEndpointConnection(value.ID())
		if err != nil {
			h.storeError(w, err, value.ID())
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", got.ETag)
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, privateEndpointConnectionWire(got), got.ETag)
	case http.MethodPut:
		h.privateEndpointConnectionUpsert(w, r, value)
	case http.MethodDelete:
		if err := h.Store.DeletePrivateEndpointConnection(value.ID()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, value.ID())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) privateEndpointConnectionUpsert(w http.ResponseWriter, r *http.Request, value model.PrivateEndpointConnection) {
	existing, existingErr := h.Store.GetPrivateEndpointConnection(value.ID())
	if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
		h.storeError(w, existingErr, value.ID())
		return
	}
	if _, err := h.Store.GetService(value.ServiceID); err != nil {
		h.storeError(w, err, value.ServiceID)
		return
	}
	if existingErr == nil {
		value = existing
	}
	var body struct {
		Properties struct {
			PrivateEndpoint *struct {
				ID *string `json:"id"`
			} `json:"privateEndpoint"`
			PrivateLinkServiceConnectionState *struct {
				Status          *string `json:"status"`
				Description     *string `json:"description"`
				ActionsRequired *string `json:"actionsRequired"`
			} `json:"privateLinkServiceConnectionState"`
		} `json:"properties"`
	}
	var document map[string]any
	if err := decodeDocument(r, &body, &document); err != nil {
		writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
		return
	}
	if body.Properties.PrivateEndpoint != nil && body.Properties.PrivateEndpoint.ID != nil {
		value.EndpointID = *body.Properties.PrivateEndpoint.ID
	}
	state := body.Properties.PrivateLinkServiceConnectionState
	if state != nil && state.Description != nil {
		value.Description = *state.Description
	}
	if state != nil && state.ActionsRequired != nil {
		value.ActionsRequired = *state.ActionsRequired
	}
	if state != nil && state.Status != nil {
		status, ok := connectionStatus(*state.Status)
		if !ok {
			writeError(w, http.StatusBadRequest, "ValidationError",
				"properties.privateLinkServiceConnectionState.status must be Pending, Approved or Rejected.",
				"properties.privateLinkServiceConnectionState.status")
			return
		}
		value.Status = status
	}
	if value.Status == "" {
		// A connection arrives Pending: it exists because a consumer asked, and
		// nobody has decided yet. Defaulting to Approved would grant access the
		// service owner never granted.
		value.Status = connectionPending
	}
	value.Document = document
	cleanResourceDocument(value.Document)
	got, err := h.Store.UpsertPrivateEndpointConnection(value)
	if err != nil {
		h.storeError(w, err, value.ID())
		return
	}
	status := http.StatusOK
	if errors.Is(existingErr, store.ErrNotFound) {
		status = http.StatusCreated
	}
	writeResource(w, status, privateEndpointConnectionWire(got), got.ETag)
}

// connectionStatus canonicalises a decision, so a caller writing "approved"
// gets the same state as one writing "Approved" and neither is stored as typed.
func connectionStatus(value string) (string, bool) {
	for _, known := range []string{connectionPending, connectionApproved, connectionRejected} {
		if strings.EqualFold(value, known) {
			return known, true
		}
	}
	return "", false
}

func privateEndpointConnectionWire(v model.PrivateEndpointConnection) map[string]any {
	result := cloneObject(v.Document)
	result["id"], result["name"] = v.ID(), v.Name
	result["type"] = "Microsoft.ApiManagement/service/privateEndpointConnections"
	properties, ok := result["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		result["properties"] = properties
	}
	state := map[string]any{"status": v.Status}
	if v.Description != "" {
		state["description"] = v.Description
	}
	if v.ActionsRequired != "" {
		state["actionsRequired"] = v.ActionsRequired
	}
	properties["privateLinkServiceConnectionState"] = state
	if v.EndpointID != "" {
		properties["privateEndpoint"] = map[string]any{"id": v.EndpointID}
	} else {
		delete(properties, "privateEndpoint")
	}
	// provisioningState is the RESOURCE's state, not the connection's decision.
	// A rejected connection is still a successfully provisioned resource, and
	// conflating the two would make a rejection look like a failed write.
	properties["provisioningState"] = "Succeeded"
	return result
}

// privateLinkResourceRoute serves the sub-resources a consumer may connect to.
//
// An APIM service exposes exactly one, `Gateway`, and it is read-only: a
// consumer needs its group id and required members to build a private endpoint.
func (h *Handler) privateLinkResourceRoute(w http.ResponseWriter, r *http.Request, rt route) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	serviceID := rt.service().ID()
	if _, err := h.Store.GetService(serviceID); err != nil {
		h.storeError(w, err, serviceID)
		return
	}
	switch len(rt.Tail) {
	case 1:
		writeJSON(w, http.StatusOK, map[string]any{"value": []any{privateLinkResourceWire(serviceID)}})
	case 2:
		if !equal(rt.Tail[1], gatewayGroupID) {
			writeError(w, http.StatusNotFound, "ResourceNotFound",
				"The only private link resource an API Management service exposes is \""+gatewayGroupID+"\".",
				serviceID+"/privateLinkResources/"+rt.Tail[1])
			return
		}
		writeJSON(w, http.StatusOK, privateLinkResourceWire(serviceID))
	default:
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The resource was not found.", serviceID)
	}
}

func privateLinkResourceWire(serviceID string) map[string]any {
	return map[string]any{
		"id":   serviceID + "/privateLinkResources/" + gatewayGroupID,
		"name": gatewayGroupID,
		"type": "Microsoft.ApiManagement/service/privateLinkResources",
		"properties": map[string]any{
			"groupId":           gatewayGroupID,
			"requiredMembers":   []any{gatewayGroupID},
			"requiredZoneNames": []any{"privatelink.azure-api.net"},
		},
	}
}

// networkStatusRoute serves the connectivity view an operator uses to find out
// whether the service can reach what it depends on.
//
// EVERY DEPENDENCY IS REPORTED SUCCESS, and that is a statement about the
// emulator rather than about a deployment: there is no virtual network here to
// be misconfigured, so there is nothing that could fail. A synthesised failure
// would be a fault this emulator invented, and a caller acting on it would be
// debugging fiction.
func (h *Handler) networkStatusRoute(w http.ResponseWriter, r *http.Request, rt route, location string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	service, err := h.Store.GetService(rt.service().ID())
	if err != nil {
		h.storeError(w, err, rt.service().ID())
		return
	}
	status := networkStatusWire()
	if location == "" {
		// The service-scoped form is a LIST, one entry per location the service
		// runs in, which for this emulator is the one it was created in.
		writeJSON(w, http.StatusOK, []any{map[string]any{"location": service.Location, "networkStatus": status}})
		return
	}
	if !strings.EqualFold(strings.ReplaceAll(location, " ", ""), strings.ReplaceAll(service.Location, " ", "")) {
		writeError(w, http.StatusNotFound, "ResourceNotFound",
			"The service is not deployed to location \""+location+"\".", rt.service().ID())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func networkStatusWire() map[string]any {
	connectivity := make([]any, 0, len(networkDependencies))
	for _, dependency := range networkDependencies {
		connectivity = append(connectivity, map[string]any{
			"name":         dependency.name,
			"status":       "success",
			"resourceType": dependency.resourceType,
			"isOptional":   dependency.optional,
		})
	}
	return map[string]any{
		"dnsServers":         []any{"127.0.0.11"},
		"connectivityStatus": connectivity,
	}
}

type networkDependency struct {
	name         string
	resourceType string
	optional     bool
	category     string
	domain       string
	ports        []int
}

// networkDependencies is what an APIM service reaches outward for. The list is
// the emulator's own, not a capture of a real deployment's, and it is short on
// purpose: an invented dependency an operator then tries to unblock in their
// firewall costs them real time.
var networkDependencies = []networkDependency{
	{name: "apim-emulator-store", resourceType: "Internal", category: "Azure Storage", domain: "table.core.windows.net", ports: []int{443}},
	{name: "apim-emulator-identity", resourceType: "External", category: "Microsoft Entra ID", domain: "login.microsoftonline.com", ports: []int{443}},
	{name: "apim-emulator-keyvault", resourceType: "External", optional: true, category: "Azure Key Vault", domain: "vault.azure.net", ports: []int{443}},
}

// outboundNetworkDependenciesRoute serves the endpoints a service reaches out
// to, which is what an operator needs to open a firewall.
func (h *Handler) outboundNetworkDependenciesRoute(w http.ResponseWriter, r *http.Request, rt route) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if _, err := h.Store.GetService(rt.service().ID()); err != nil {
		h.storeError(w, err, rt.service().ID())
		return
	}
	byCategory := map[string][]any{}
	order := make([]string, 0, len(networkDependencies))
	for _, dependency := range networkDependencies {
		details := make([]any, 0, len(dependency.ports))
		for _, port := range dependency.ports {
			details = append(details, map[string]any{"port": port, "region": "Global"})
		}
		if _, seen := byCategory[dependency.category]; !seen {
			order = append(order, dependency.category)
		}
		byCategory[dependency.category] = append(byCategory[dependency.category], map[string]any{
			"domainName":      dependency.domain,
			"endpointDetails": details,
		})
	}
	values := make([]any, 0, len(order))
	for _, category := range order {
		values = append(values, map[string]any{"category": category, "endpoints": byCategory[category]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": values})
}
