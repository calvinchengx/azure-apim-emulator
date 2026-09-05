package arm

import (
	"net/http"
	"net/http/httptest"
	"strings"
)

func (h *Handler) handleConditionalRequest(w http.ResponseWriter, r *http.Request, rt route) bool {
	ifMatch, hasIfMatch, validIfMatch := entityTags(r.Header.Values("If-Match"))
	ifNoneMatch, hasIfNoneMatch, validIfNoneMatch := entityTags(r.Header.Values("If-None-Match"))
	if !validIfMatch || !validIfNoneMatch {
		writeError(w, http.StatusBadRequest, "InvalidHeaderValue", "A conditional request header contains an invalid entity tag.", "")
		return true
	}
	if requiresIfMatch(rt, r.Method) && !hasIfMatch {
		writeError(w, http.StatusBadRequest, "MissingRequiredHeader", "The If-Match header is required for this operation.", "If-Match")
		return true
	}
	if !hasIfMatch && !hasIfNoneMatch {
		return false
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		response := httptest.NewRecorder()
		h.routeRequest(response, r, rt)
		etag := response.Header().Get("ETag")
		if response.Code == http.StatusNotFound && hasIfMatch {
			writePreconditionFailed(w, r.URL.Path)
			return true
		}
		if response.Code >= 200 && response.Code < 300 {
			if hasIfMatch && !strongTagMatch(ifMatch, etag, true) {
				writePreconditionFailed(w, r.URL.Path)
				return true
			}
			if hasIfNoneMatch && weakTagMatch(ifNoneMatch, etag, true) {
				copyHeaders(w.Header(), response.Header())
				w.Header().Del("Content-Type")
				w.WriteHeader(http.StatusNotModified)
				return true
			}
		}
		copyRecordedResponse(w, response)
		return true
	case http.MethodPut, http.MethodPatch, http.MethodDelete:
		probe := httptest.NewRecorder()
		probeRequest := r.Clone(r.Context())
		probeRequest.Method = http.MethodGet
		probeRequest.Header = r.Header.Clone()
		probeRequest.Header.Del("If-Match")
		probeRequest.Header.Del("If-None-Match")
		h.routeRequest(probe, probeRequest, rt)
		exists := probe.Code >= 200 && probe.Code < 300
		etag := probe.Header().Get("ETag")
		if hasIfMatch && !strongTagMatch(ifMatch, etag, exists) {
			writePreconditionFailed(w, r.URL.Path)
			return true
		}
		if hasIfNoneMatch && weakTagMatch(ifNoneMatch, etag, exists) {
			writePreconditionFailed(w, r.URL.Path)
			return true
		}
	}
	return false
}

func requiresIfMatch(rt route, method string) bool {
	// Tenant access is the only family whose PUT requires an entity tag.
	// Microsoft marks `ifMatch` required on BOTH `TenantAccess_Create` and
	// `TenantAccess_Update`, which is why this check comes before the
	// PATCH/DELETE narrowing below rather than inside it: the two rows always
	// exist, so `If-Match: *` is a real precondition there and not the
	// no-op it is on a create.
	if len(rt.Tail) == 2 && equal(rt.Tail[0], "tenant") {
		return method == http.MethodPut || method == http.MethodPatch
	}
	if method != http.MethodPatch && method != http.MethodDelete {
		return false
	}
	if len(rt.Tail) == 2 {
		resource := rt.Tail[0]
		if method == http.MethodPatch {
			return oneOf(resource, "apis", "apiVersionSets", "namedValues", "backends", "caches", "identityProviders", "openidConnectProviders", "authorizationServers", "documentations", "gateways", "tags", "groups", "users", "loggers", "diagnostics", "products", "subscriptions")
		}
		return oneOf(resource, "apis", "apiVersionSets", "namedValues", "backends", "caches", "identityProviders", "openidConnectProviders", "authorizationServers", "documentations", "certificates", "gateways", "tags", "groups", "users", "policyFragments", "loggers", "diagnostics", "products", "subscriptions")
	}
	if len(rt.Tail) != 4 {
		return false
	}
	child := strings.ToLower(rt.Tail[2])
	// A gateway's hostnames and certificate authorities require If-Match on
	// delete, but its API associations do NOT: an association is a link, and
	// the SDK's signature for removing one carries no entity tag.
	// `child` is already lowercased above, so these candidates must be too --
	// a mixed-case candidate here matches nothing and the branch goes quiet.
	if equal(rt.Tail[0], "gateways") {
		return method == http.MethodDelete && oneOf(child, "hostnameconfigurations", "certificateauthorities")
	}
	if !equal(rt.Tail[0], "apis") {
		return false
	}
	if method == http.MethodPatch {
		return oneOf(child, "operations", "releases", "diagnostics")
	}
	return oneOf(child, "operations", "schemas", "releases", "diagnostics")
}

func entityTags(values []string) ([]string, bool, bool) {
	if len(values) == 0 {
		return nil, false, true
	}
	var result []string
	for _, value := range values {
		for _, tag := range strings.Split(value, ",") {
			tag = strings.TrimSpace(tag)
			if tag != "*" && !validEntityTag(tag) {
				return nil, true, false
			}
			result = append(result, tag)
		}
	}
	return result, true, len(result) > 0
}

func validEntityTag(value string) bool {
	value = strings.TrimPrefix(value, "W/")
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return false
	}
	for _, character := range value[1 : len(value)-1] {
		if character == '"' || character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}

func strongTagMatch(candidates []string, current string, exists bool) bool {
	for _, candidate := range candidates {
		if candidate == "*" {
			return exists
		}
		if exists && !strings.HasPrefix(candidate, "W/") && candidate == current {
			return true
		}
	}
	return false
}

func weakTagMatch(candidates []string, current string, exists bool) bool {
	for _, candidate := range candidates {
		if candidate == "*" {
			return exists
		}
		if exists && strings.TrimPrefix(candidate, "W/") == strings.TrimPrefix(current, "W/") {
			return true
		}
	}
	return false
}

func copyHeaders(target, source http.Header) {
	for key, values := range source {
		target[key] = append([]string(nil), values...)
	}
}

func copyRecordedResponse(w http.ResponseWriter, response *httptest.ResponseRecorder) {
	copyHeaders(w.Header(), response.Header())
	w.WriteHeader(response.Code)
	_, _ = w.Write(response.Body.Bytes())
}

func writePreconditionFailed(w http.ResponseWriter, target string) {
	writeError(w, http.StatusPreconditionFailed, "PreconditionFailed", "The condition specified using HTTP conditional header(s) is not met.", target)
}
