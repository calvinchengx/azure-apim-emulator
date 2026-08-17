package arm

import (
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/auth"
	"github.com/calvinchengx/azure-apim-emulator/internal/rbac"
)

// authorize evaluates the caller's role assignments, and reports whether the
// request may proceed. It writes the refusal itself when it does not.
//
// Off by default. With enforcement disabled a valid ARM token gets full access,
// which is what every existing caller assumes and what keeps the emulator
// usable without anyone having to grant themselves a role first. Turning it on
// is opting in to being refused.
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request, principal *auth.Principal, path string) bool {
	if !h.EnforceRBAC {
		return true
	}
	if principal == nil || principal.ID == "" {
		// Enforcement with no identity to evaluate would deny everything, which
		// reads as a broken emulator rather than a refused request.
		writeError(w, http.StatusForbidden, "AuthorizationFailed",
			"RBAC enforcement is enabled but the request carried no principal.", path)
		return false
	}
	scope, action := scopeAndAction(r.Method, path)
	if scope == "" {
		return true
	}
	// The configured owner's access does not come from an assignment, exactly
	// as a subscription owner's does not in Azure. Without this the first
	// assignment could never be made, because making one is itself an action
	// that needs a role.
	if h.RBACOwner != "" && strings.EqualFold(principal.ID, h.RBACOwner) {
		return true
	}
	assignments, err := h.Store.ListRoleAssignments()
	if err != nil {
		h.storeError(w, err, path)
		return false
	}
	decision := rbac.Authorize(principal.ID, action, scope, assignments, rbac.BuiltInRoles())
	if decision.Allowed {
		return true
	}
	// ARM's own refusal shape and status. A client library turns this into a
	// permissions error; anything else and it reports a transport failure or a
	// missing resource, neither of which tells the caller to grant a role.
	writeError(w, http.StatusForbidden, "AuthorizationFailed",
		"The client '"+principal.ID+"' with object id '"+principal.ID+"' does not have authorization to perform action '"+
			string(action)+"' over scope '"+scope+"' or the scope is invalid.", scope)
	return false
}

// scopeAndAction derives what is being touched and how, from an APIM path.
//
// The scope is the full resource ID, because that is what an assignment is
// compared against; the action is derived from the resource TYPES in the path,
// because that is how every published role is written.
func scopeAndAction(method, path string) (string, rbac.Action) {
	parts := split(path)
	// Everything up to and including the provider is the ARM prefix; the APIM
	// resource path is what follows.
	provider := -1
	for i := 0; i+1 < len(parts); i++ {
		if equal(parts[i], "providers") && equal(parts[i+1], "Microsoft.ApiManagement") {
			provider = i + 2
			break
		}
	}
	if provider < 0 || provider >= len(parts) {
		// A subscription or resource-group path with no APIM resource. Nothing
		// here is an APIM action, so there is nothing to authorize.
		return "", ""
	}
	return "/" + strings.Join(parts, "/"), rbac.ActionFor(method, parts[provider:])
}
