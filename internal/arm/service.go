package arm

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

var supportedVersions = map[string]bool{"2021-08-01": true, "2022-08-01": true, "2024-05-01": true}

// authorizationVersions are Microsoft.Authorization's own API versions, which
// are NOT APIM's. A client managing role assignments sends the version its own
// provider publishes, so validating it against the APIM list rejects every such
// request before it is even routed.
var authorizationVersions = map[string]bool{
	"2015-07-01": true, "2018-01-01-preview": true, "2020-04-01-preview": true,
	"2020-08-01-preview": true, "2020-10-01-preview": true, "2022-04-01": true,
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
		// A tier is not just a price: it decides how far the service scales and
		// which capabilities exist at all. Validating here is what stops a
		// caller building a topology locally that Azure refuses outright.
		serviceTier, message := validateSKU(body.SKU.Name, body.SKU.Capacity)
		if message != "" {
			writeError(w, http.StatusBadRequest, "ValidationError", message, "sku")
			return
		}
		if message := validateAdditionalLocations(document, serviceTier); message != "" {
			writeError(w, http.StatusBadRequest, "ValidationError", message, "properties.additionalLocations")
			return
		}
		projectAdditionalLocations(document, rt.ServiceName)
		_, existingErr := h.Store.GetService(value.ID())
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			h.storeError(w, existingErr, value.ID())
			return
		}
		value.Location, value.SKUName, value.SKUCapacity = body.Location, body.SKU.Name, body.SKU.Capacity
		value.PublisherName, value.PublisherEmail, value.Document = body.Properties.PublisherName, body.Properties.PublisherEmail, document
		// A hostname configuration carries a write-only PFX and read-only facts
		// about it in one object. Resolving here, on the way in, is what lets
		// the secret be dropped before it is ever stored.
		resolveHostnameCertificates(value.Document, time.Now().UTC())
		// No defaulting: validateSKU above refuses an absent or unknown tier, so
		// a service reaching this point named one. Defaulting here would have
		// been dead code, and worse, would have disagreed with the validation
		// about what an empty sku means.
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

// parseServiceProviderAction recognises the two SUBSCRIPTION-scoped operations
// in the `ApiManagementService` group. They are siblings of `service` rather
// than children of one, so they are answered before the service parser runs,
// the same way the SKU catalogue is.
func parseServiceProviderAction(parts []string) (string, bool) {
	if len(parts) == 5 && equal(parts[0], "subscriptions") && equal(parts[2], "providers") &&
		equal(parts[3], "Microsoft.ApiManagement") &&
		oneOf(strings.ToLower(parts[4]), "checknameavailability", "getdomainownershipidentifier") {
		return strings.ToLower(parts[4]), true
	}
	return "", false
}

// serviceNamePattern is Microsoft's own constraint on `serviceName`, taken from
// the parameter definition in `apimanagement.json` at the pinned spec commit
// (`minLength: 1`, `maxLength: 50`, this pattern) rather than from a
// recollection of the portal's error message.
var serviceNamePattern = regexp.MustCompile(`^[a-zA-Z](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$`)

// serviceProviderAction serves `checkNameAvailability` and
// `getDomainOwnershipIdentifier`.
func (h *Handler) serviceProviderAction(w http.ResponseWriter, r *http.Request, subscriptionID, action string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if action == "getdomainownershipidentifier" {
		// DERIVED from the subscription rather than minted fresh, because the
		// value's whole purpose is to be published in a DNS TXT record and then
		// checked later. One that changed per call would be useless in exactly
		// the workflow it exists for, and the emulator would look fine while
		// every verification failed.
		sum := sha256.Sum256([]byte("domain-ownership:" + strings.ToLower(subscriptionID)))
		writeJSON(w, http.StatusOK, map[string]any{
			"domainOwnershipIdentifier": base64.StdEncoding.EncodeToString(sum[:]),
		})
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "InvalidRequestContent", "malformed request body: "+err.Error(), "")
		return
	}
	writeJSON(w, http.StatusOK, h.nameAvailability(body.Name))
}

// nameAvailability answers the three cases Microsoft's `NameAvailabilityReason`
// names, and answers them for real.
//
// The namespace is checked across ALL subscriptions, not just the caller's,
// because an APIM service name becomes `<name>.azure-api.net`: it is a DNS
// label, and DNS has no idea whose subscription it is. Scoping the check to one
// subscription would report a name available that a create then refuses.
func (h *Handler) nameAvailability(name string) map[string]any {
	if name == "" || len(name) > 50 || !serviceNamePattern.MatchString(name) {
		return map[string]any{
			"nameAvailable": false,
			"reason":        "Invalid",
			"message": "A service name must be 1-50 characters, start with a letter, end with a letter or digit, " +
				"and contain only letters, digits and hyphens.",
		}
	}
	services, err := h.Store.ListServices()
	if err != nil {
		// Unknown is not available. Reporting a name free because the lookup
		// broke is the one answer that cannot be recovered from: the caller
		// goes on to create, and the create is what fails.
		return map[string]any{
			"nameAvailable": false,
			"reason":        "AlreadyExists",
			"message":       "The name could not be checked, so it is not being reported as available.",
		}
	}
	for _, service := range services {
		if equal(service.Name, name) {
			return map[string]any{
				"nameAvailable": false,
				"reason":        "AlreadyExists",
				"message":       name + " is already in use. Please select a different name.",
			}
		}
	}
	return map[string]any{"nameAvailable": true, "reason": "Valid"}
}

// serviceSsoToken serves `POST /service/{name}/getssotoken`.
//
// The redirect URI points at THIS emulator's portal and resolves. Azure's
// example returns `https://<service>.portal.azure-api.net/signin-sso?token=...`,
// and returning that shape here would hand a caller a link to a service that
// does not exist. The token is opaque and is NOT consumed: the emulator's
// portal has no session to establish, so this proves the operation answers with
// a working URI and claims nothing about single sign-on.
func (h *Handler) serviceSsoToken(w http.ResponseWriter, r *http.Request, rt route) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if _, err := h.Store.GetService(rt.service().ID()); err != nil {
		h.storeError(w, err, rt.service().ID())
		return
	}
	token := url.Values{"token": []string{store.NewOpaqueID()}}
	writeJSON(w, http.StatusOK, map[string]any{
		"redirectUri": absolute(r, "/_emulator/portal/?"+token.Encode()),
	})
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
