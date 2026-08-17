package arm

import (
	"net/http"
	"sort"
	"strings"
)

// Tiers and SKUs.
//
// The table below is the useful part: an APIM tier is not just a price, it is
// which capabilities exist at all. Recording that in one place is what lets the
// emulator refuse what a tenant would refuse, and what lets the ledger state
// precisely which capabilities are gated rather than gesturing at "tier limits".

// tier describes one APIM SKU: how far it scales, and what it can do.
type tier struct {
	Name string
	// MinCapacity and MaxCapacity bound the units a service may run. A tier
	// whose min and max are both 1 cannot be scaled at all, which is a
	// different refusal from asking for more than the maximum.
	MinCapacity int
	MaxCapacity int
	// Capabilities are the features this tier has. Absence is the point: a
	// capability missing here is one Azure refuses on this tier.
	Capabilities map[string]bool
}

// Capability names, referenced by the gate and by the ledger.
const (
	capabilityWorkspaces        = "workspaces"
	capabilityMultiRegion       = "multi-region"
	capabilitySelfHostedGateway = "self-hosted-gateway"
	capabilityVirtualNetwork    = "virtual-network"
	capabilityAvailabilityZones = "availability-zones"
	capabilityClientCertificate = "client-certificate-authority"
)

// tiers is the SKU catalogue.
//
// DERIVED FROM MICROSOFT'S PUBLISHED FEATURE-BY-TIER TABLE, not from a capture
// of a subscription's own SKU list, and the ledger says so. Two consequences
// worth stating rather than discovering: the capacity ceilings are Azure's
// documented defaults and a real subscription's quota may be lower; and the
// v2 tiers are deliberately absent, because their capability matrix differs
// from the classic ones in ways this has not verified.
var tiers = map[string]tier{
	"developer": {
		Name: "Developer", MinCapacity: 1, MaxCapacity: 1,
		Capabilities: map[string]bool{
			capabilitySelfHostedGateway: true,
			capabilityVirtualNetwork:    true,
			capabilityClientCertificate: true,
		},
	},
	"consumption": {
		Name: "Consumption", MinCapacity: 0, MaxCapacity: 0,
		Capabilities: map[string]bool{},
	},
	"basic": {
		Name: "Basic", MinCapacity: 1, MaxCapacity: 2,
		Capabilities: map[string]bool{capabilityClientCertificate: true},
	},
	"standard": {
		Name: "Standard", MinCapacity: 1, MaxCapacity: 4,
		Capabilities: map[string]bool{capabilityClientCertificate: true},
	},
	"premium": {
		Name: "Premium", MinCapacity: 1, MaxCapacity: 12,
		Capabilities: map[string]bool{
			capabilityWorkspaces:        true,
			capabilityMultiRegion:       true,
			capabilitySelfHostedGateway: true,
			capabilityVirtualNetwork:    true,
			capabilityAvailabilityZones: true,
			capabilityClientCertificate: true,
		},
	},
}

// lookupTier finds a tier by name, case-insensitively.
func lookupTier(name string) (tier, bool) {
	found, ok := tiers[strings.ToLower(strings.TrimSpace(name))]
	return found, ok
}

// tierNames lists the catalogue in a stable order, so a refusal message and a
// listing do not reorder between runs.
func tierNames() []string {
	names := make([]string, 0, len(tiers))
	for _, value := range tiers {
		names = append(names, value.Name)
	}
	sort.Strings(names)
	return names
}

// validateSKU checks a service's requested tier and capacity.
//
// This is NOT behind the enforcement flag: it is validation of the service
// resource itself, which Azure always applies, and every existing caller
// already sends a valid combination.
func validateSKU(name string, capacity int) (tier, string) {
	found, ok := lookupTier(name)
	if !ok {
		return tier{}, "sku.name must be one of " + strings.Join(tierNames(), ", ") + "."
	}
	if capacity < found.MinCapacity || capacity > found.MaxCapacity {
		if found.MinCapacity == found.MaxCapacity {
			return tier{}, "the " + found.Name + " tier runs exactly " +
				itoa(found.MinCapacity) + " unit(s) and cannot be scaled."
		}
		return tier{}, "the " + found.Name + " tier runs between " +
			itoa(found.MinCapacity) + " and " + itoa(found.MaxCapacity) + " units."
	}
	return found, ""
}

// itoa avoids importing strconv for two call sites in message text.
func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := ""
	for value > 0 {
		digits = string(rune('0'+value%10)) + digits
		value /= 10
	}
	return digits
}

// skuRoute serves the SKUs a given service may move to.
//
// Scoped to the service because that is the question being asked: not "what
// does Azure sell" but "what can THIS service become", which is why a
// Consumption service and a Premium one get different answers.
func (h *Handler) skuRoute(w http.ResponseWriter, r *http.Request, rt route) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	service, err := h.Store.GetService(rt.service().ID())
	if err != nil {
		h.storeError(w, err, rt.service().ID())
		return
	}
	current, known := lookupTier(service.SKUName)
	values := make([]any, 0, len(tiers))
	for _, name := range tierNames() {
		candidate, _ := lookupTier(name)
		// A Consumption service cannot be scaled up into the dedicated tiers,
		// and a dedicated one cannot be moved to Consumption. Listing them
		// anyway would offer a move that always fails.
		if known && (candidate.MaxCapacity == 0) != (current.MaxCapacity == 0) {
			continue
		}
		values = append(values, map[string]any{
			"resourceType": "Microsoft.ApiManagement/service",
			"sku":          map[string]any{"name": candidate.Name},
			"capacity":     capacityWire(candidate),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": values})
}

func capacityWire(value tier) map[string]any {
	scaleType := "Manual"
	if value.MinCapacity == value.MaxCapacity {
		scaleType = "None"
	}
	return map[string]any{
		"minimum":   value.MinCapacity,
		"maximum":   value.MaxCapacity,
		"default":   value.MinCapacity,
		"scaleType": scaleType,
	}
}

// providerSKURoute serves the subscription-wide SKU catalogue.
func (h *Handler) providerSKURoute(w http.ResponseWriter, r *http.Request, location string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	values := make([]any, 0, len(tiers))
	for _, name := range tierNames() {
		candidate, _ := lookupTier(name)
		capabilities := make([]any, 0, len(candidate.Capabilities))
		for _, capability := range sortedCapabilities(candidate) {
			capabilities = append(capabilities, map[string]any{"name": capability, "value": "True"})
		}
		values = append(values, map[string]any{
			"resourceType": "Microsoft.ApiManagement/service",
			"name":         candidate.Name,
			"tier":         candidate.Name,
			"capacity":     capacityWire(candidate),
			"locations":    []any{location},
			"capabilities": capabilities,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": values})
}

func sortedCapabilities(value tier) []string {
	names := make([]string, 0, len(value.Capabilities))
	for name := range value.Capabilities {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// regionRoute serves the regions a service is deployed to.
//
// The master region is where the service was created; every additional
// location adds one. A caller uses this to find out where a request will be
// served from, which is why the flag distinguishing them matters.
func (h *Handler) regionRoute(w http.ResponseWriter, r *http.Request, rt route) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	service, err := h.Store.GetService(rt.service().ID())
	if err != nil {
		h.storeError(w, err, rt.service().ID())
		return
	}
	values := []any{map[string]any{"name": service.Location, "isMasterRegion": true, "isDeleted": false}}
	for _, additional := range additionalLocationList(service.Document) {
		location, _ := additional["location"].(string)
		if strings.TrimSpace(location) == "" {
			continue
		}
		values = append(values, map[string]any{"name": location, "isMasterRegion": false, "isDeleted": false})
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": values, "count": len(values)})
}

// additionalLocationList returns a service document's additional locations.
func additionalLocationList(document map[string]any) []map[string]any {
	properties, _ := document["properties"].(map[string]any)
	entries, _ := properties["additionalLocations"].([]any)
	values := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		if location, ok := entry.(map[string]any); ok {
			values = append(values, location)
		}
	}
	return values
}

// validateAdditionalLocations checks the extra regions a service asks for.
//
// Multi-region is Premium only, and each region carries its own SKU and
// capacity. Accepting them on a lesser tier would let a caller build a topology
// here that Azure refuses outright.
func validateAdditionalLocations(document map[string]any, serviceTier tier) string {
	locations := additionalLocationList(document)
	if len(locations) == 0 {
		return ""
	}
	if !serviceTier.Capabilities[capabilityMultiRegion] {
		return "properties.additionalLocations requires the Premium tier; the " +
			serviceTier.Name + " tier is single-region."
	}
	for _, location := range locations {
		name, _ := location["location"].(string)
		if strings.TrimSpace(name) == "" {
			return "each entry in properties.additionalLocations requires a location."
		}
		sku, _ := location["sku"].(map[string]any)
		skuName, _ := sku["name"].(string)
		capacity := 1
		if raw, ok := sku["capacity"].(float64); ok {
			capacity = int(raw)
		}
		if _, message := validateSKU(skuName, capacity); message != "" {
			return "properties.additionalLocations[" + name + "].sku: " + message
		}
	}
	return ""
}

// projectAdditionalLocations fills in what the service reports back about each
// extra region.
func projectAdditionalLocations(document map[string]any, serviceName string) {
	for _, location := range additionalLocationList(document) {
		name, _ := location["location"].(string)
		location["gatewayRegionalUrl"] = "https://" + serviceName + "-" +
			strings.ToLower(strings.ReplaceAll(name, " ", "")) + ".regional.azure-api.localhost"
		if _, stated := location["disableGateway"]; !stated {
			location["disableGateway"] = false
		}
	}
}

// requireCapability refuses a request whose service tier does not have the
// capability it needs.
//
// It reports whether the caller may proceed, and answers the request itself
// when not, so a call site is one `if !h.requireCapability(...) { return }`.
//
// OFF BY DEFAULT. With enforcement off this always allows, which makes the
// emulator more permissive than a tenant: a Developer service can create
// workspaces here and cannot in Azure. That is a deliberate trade for not
// breaking every existing caller, not a claim that the tiers match.
func (h *Handler) requireCapability(w http.ResponseWriter, serviceID, capability string) bool {
	if !h.EnforceTiers {
		return true
	}
	service, err := h.Store.GetService(serviceID)
	if err != nil {
		h.storeError(w, err, serviceID)
		return false
	}
	found, known := lookupTier(service.SKUName)
	if known && found.Capabilities[capability] {
		return true
	}
	writeError(w, http.StatusBadRequest, "ValidationError",
		"The "+service.SKUName+" tier does not support "+capability+
			". Azure offers it on: "+strings.Join(tiersWith(capability), ", ")+".",
		"sku.name")
	return false
}

// tiersWith names the tiers offering a capability, so a refusal tells the
// caller what to change rather than only that they were refused.
func tiersWith(capability string) []string {
	var names []string
	for _, name := range tierNames() {
		if candidate, _ := lookupTier(name); candidate.Capabilities[capability] {
			names = append(names, candidate.Name)
		}
	}
	return names
}
