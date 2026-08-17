package arm

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

// Link resources are Azure's ARM-native spelling of associations this emulator
// already had: a product's APIs and groups, and a tag's APIs, operations and
// products. `PUT /products/p/apis/a` and `PUT /products/p/apiLinks/x` describe
// the SAME association, and Azure's own SDK exposes both.
//
// So links are a PROJECTION, not a second store. Giving them their own table
// would let the two surfaces disagree about whether an API is in a product,
// which has no local symptom and breaks the first time the flow runs against a
// real tenant. The only thing a link adds is a name, which is why the name is a
// column on the association.
//
// WHAT IS NOT CAPTURED: Azure decides what a link is called when the
// association was made through the older path, and that rule is not in the
// specification. This emulator derives the name from the target's own name,
// disambiguating deterministically on collision. That is a decision, not an
// observation, and the parity ledger says so.

// linkSurface is one link collection: what it points at, and how to change it.
type linkSurface struct {
	// parentID is the product or tag the links hang off.
	parentID string
	// segment is the path segment, such as `apiLinks`.
	segment string
	// property is the single required body field, such as `apiId`. It carries
	// the FULL ARM id of the target, not a bare name.
	property string
	// armType is the resource type reported on the wire.
	armType string
	kind    store.LinkKind
	// targets are the currently associated target IDs.
	targets []string
	// verify reports whether a target exists and is the right kind of thing.
	verify func(targetID string) error
	attach func(targetID string) error
	detach func(targetID string) error
}

// linkRoute serves one link collection or one link within it.
func (h *Handler) linkRoute(w http.ResponseWriter, r *http.Request, surface linkSurface, name string) {
	stored, err := h.Store.LinkNames(surface.kind, surface.parentID)
	if err != nil {
		h.storeError(w, err, surface.parentID)
		return
	}
	names := effectiveLinkNames(surface.targets, stored)

	if name == "" {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		resources := make([]map[string]any, 0, len(surface.targets))
		for _, targetID := range surface.targets {
			resources = append(resources, linkWire(surface, names[targetID], targetID))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": resources, "count": len(resources)})
		return
	}

	targetID := ""
	for candidate, linkName := range names {
		if equal(linkName, name) {
			targetID = candidate
			break
		}
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if targetID == "" {
			writeError(w, http.StatusNotFound, "ResourceNotFound",
				"The requested link was not found.", surface.parentID+"/"+surface.segment+"/"+name)
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeResource(w, http.StatusOK, linkWire(surface, name, targetID), "")
	case http.MethodPut:
		h.putLink(w, r, surface, names, name, targetID)
	case http.MethodDelete:
		if targetID == "" {
			writeError(w, http.StatusNotFound, "ResourceNotFound",
				"The requested link was not found.", surface.parentID+"/"+surface.segment+"/"+name)
			return
		}
		if err := surface.detach(targetID); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.storeError(w, err, surface.parentID)
			return
		}
		if err := h.activate(); err != nil {
			writeError(w, http.StatusInternalServerError, "ConfigurationInvalid", err.Error(), surface.parentID)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) putLink(w http.ResponseWriter, r *http.Request, surface linkSurface,
	names map[string]string, name, existingTarget string) {
	var body struct {
		Properties map[string]string `json:"properties"`
	}
	var document map[string]any
	if err := decodeDocument(r, &body, &document); err != nil {
		writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error(), "")
		return
	}
	targetID := strings.TrimSpace(body.Properties[surface.property])
	if targetID == "" {
		writeError(w, http.StatusBadRequest, "ValidationError",
			"properties."+surface.property+" is required and must be a full resource ID.", surface.property)
		return
	}
	// A target that does not exist is a bad REQUEST, not a missing route. A 404
	// here would be indistinguishable from the link path not being served at
	// all, which is the distinction the operation inventory depends on.
	if err := surface.verify(targetID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusBadRequest, "ValidationError",
				"properties."+surface.property+" does not name an existing resource.", targetID)
			return
		}
		h.storeError(w, err, targetID)
		return
	}
	// One association is one link. Letting a second name point at an
	// already-linked target would give one association two identities, and
	// deleting either would leave the other dangling.
	if taken, ok := linkNameOwner(names, name); ok && !equal(taken, targetID) {
		writeError(w, http.StatusBadRequest, "ValidationError",
			"another link in this collection already uses this name.", name)
		return
	}

	created := existingTarget == ""
	if err := surface.attach(targetID); err != nil {
		h.storeError(w, err, surface.parentID)
		return
	}
	if err := h.Store.SetLinkName(surface.kind, surface.parentID, targetID, name); err != nil {
		h.storeError(w, err, surface.parentID)
		return
	}
	if err := h.activate(); err != nil {
		writeError(w, http.StatusBadRequest, "ConfigurationInvalid", err.Error(), surface.parentID)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeResource(w, status, linkWire(surface, name, targetID), "")
}

func linkNameOwner(names map[string]string, name string) (string, bool) {
	for targetID, linkName := range names {
		if equal(linkName, name) {
			return targetID, true
		}
	}
	return "", false
}

func linkWire(surface linkSurface, name, targetID string) map[string]any {
	return map[string]any{
		"id":         surface.parentID + "/" + surface.segment + "/" + name,
		"name":       name,
		"type":       surface.armType,
		"properties": map[string]any{surface.property: targetID},
	}
}

// effectiveLinkNames decides what each association is called.
//
// A link created through the link surface keeps the name the client chose. One
// created through the older association path has none, so it is named after the
// target: `.../apis/orders` becomes the link `orders`. Where that collides —
// two APIs can each own an operation called `get-invoice` — the name grows
// leftwards through the target's ANCESTOR NAMES, giving `billing-get-invoice`.
//
// It steps two segments at a time because an ARM id alternates collection and
// name (`/apis/billing/operations/get-invoice`), so every other segment is a
// literal like `operations`, which identifies nothing. Growing by one would
// produce `operations-get-invoice` for both colliding operations and not
// actually disambiguate them.
//
// Names are assigned in sorted order so the result depends on the set of
// associations rather than on the order they were created in.
func effectiveLinkNames(targets []string, stored map[string]string) map[string]string {
	names := map[string]string{}
	taken := map[string]bool{}
	remaining := make([]string, 0, len(targets))
	for _, targetID := range targets {
		if name := stored[targetID]; name != "" {
			names[targetID] = name
			taken[strings.ToLower(name)] = true
			continue
		}
		remaining = append(remaining, targetID)
	}
	sort.Strings(remaining)
	for _, targetID := range remaining {
		segments := strings.Split(strings.Trim(targetID, "/"), "/")
		name := segments[len(segments)-1]
		for depth := 3; taken[strings.ToLower(name)] && depth <= len(segments); depth += 2 {
			name = segments[len(segments)-depth] + "-" + name
		}
		names[targetID] = name
		taken[strings.ToLower(name)] = true
	}
	return names
}

// productLinkSurface builds the surface for a product's API or group links.
func (h *Handler) productLinkSurface(product model.Product, segment string) (linkSurface, error) {
	surface := linkSurface{parentID: product.ID(), segment: segment}
	if equal(segment, "apiLinks") {
		ids, err := h.Store.ListProductAPIs(product.ID())
		if err != nil {
			return surface, err
		}
		surface.property, surface.kind, surface.targets = "apiId", store.LinkProductAPIKind, ids
		surface.verify = func(id string) error { _, err := h.Store.GetAPI(id); return err }
		surface.attach = func(id string) error { return h.Store.LinkProductAPI(product.ID(), id) }
		surface.detach = func(id string) error { return h.Store.UnlinkProductAPI(product.ID(), id) }
		return surface, nil
	}
	groups, err := h.Store.ListProductGroups(product.ID())
	if err != nil {
		return surface, err
	}
	ids := make([]string, 0, len(groups))
	for _, group := range groups {
		ids = append(ids, group.ID())
	}
	surface.property, surface.kind, surface.targets = "groupId", store.LinkProductGroupKind, ids
	surface.verify = func(id string) error { _, err := h.Store.GetGroup(id); return err }
	surface.attach = func(id string) error { return h.Store.LinkProductGroup(product.ID(), id) }
	surface.detach = func(id string) error { return h.Store.UnlinkProductGroup(product.ID(), id) }
	return surface, nil
}

// tagLinkSurface builds the surface for a tag's API, operation or product links.
//
// One tag holds all three kinds at once, so each collection is the tagged
// resources FILTERED to the kind it publishes. Without the filter, a tag
// carrying an API and a product would report both in every collection.
func (h *Handler) tagLinkSurface(tag model.Tag, segment string) (linkSurface, error) {
	surface := linkSurface{parentID: tag.ID(), segment: segment, kind: store.LinkResourceTagKind}
	tagged, err := h.Store.ListTaggedResources(tag.ID())
	if err != nil {
		return surface, err
	}
	switch {
	case equal(segment, "apiLinks"):
		surface.property = "apiId"
		surface.verify = func(id string) error { _, err := h.Store.GetAPI(id); return err }
	case equal(segment, "operationLinks"):
		surface.property = "operationId"
		surface.verify = func(id string) error { _, err := h.Store.GetOperation(id); return err }
	default:
		surface.property = "productId"
		surface.verify = func(id string) error { _, err := h.Store.GetProduct(id); return err }
	}
	for _, resourceID := range tagged {
		if taggedResourceKind(resourceID) == surface.property {
			surface.targets = append(surface.targets, resourceID)
		}
	}
	surface.attach = func(id string) error { return h.Store.AssignTag(id, tag.ID()) }
	surface.detach = func(id string) error { return h.Store.DetachTag(id, tag.ID()) }
	return surface, nil
}

// taggedResourceKind reports which link collection a tagged resource belongs
// to, named by the property that would carry it.
func taggedResourceKind(resourceID string) string {
	lowered := strings.ToLower(resourceID)
	switch {
	case strings.Contains(lowered, "/operations/"):
		return "operationId"
	case strings.Contains(lowered, "/apis/"):
		return "apiId"
	case strings.Contains(lowered, "/products/"):
		return "productId"
	default:
		return ""
	}
}

// isLinkSegment reports whether a path segment names a link collection.
func isLinkSegment(segment string, allowed ...string) bool {
	for _, candidate := range allowed {
		if equal(segment, candidate) {
			return true
		}
	}
	return false
}

// linkType builds the ARM type string, which differs at workspace scope
// because a workspace link is a different resource type in Azure, not the same
// type in a different place.
func linkType(workspace bool, parent, segment string) string {
	if workspace {
		return "Microsoft.ApiManagement/service/workspaces/" + parent + "/" + segment
	}
	return "Microsoft.ApiManagement/service/" + parent + "/" + segment
}
