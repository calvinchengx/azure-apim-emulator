// Package arm implements the Microsoft.ApiManagement management surface.
package arm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/calvinchengx/azure-apim-emulator/internal/auth"
	"github.com/calvinchengx/azure-apim-emulator/internal/keyvault"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

// Handler serves the P0 APIM ARM resources.
type Handler struct {
	Store    *store.Store
	Auth     auth.RequestValidator
	Activate func() error
	// EnforceRBAC evaluates role assignments before each request. Off by
	// default, which is what every existing caller assumes.
	EnforceRBAC bool
	// EnforceTiers refuses capabilities the service's SKU does not have. Off
	// by default: see internal/config for why, and for why that default is
	// itself a divergence rather than a neutral choice.
	EnforceTiers bool
	// RBACOwner holds Owner at subscription scope while enforcement is on, so
	// the first assignment can be created at all.
	RBACOwner      string
	ValidatePolicy func(string) error
	// ValidateResolverPolicy validates a GraphQL resolver's <http-data-source>.
	ValidateResolverPolicy func(string) error
	// LoginLink and ConfirmConsent are the credential-manager consent handshake.
	// Supplied by the server, which owns the OAuth2 client; the ARM handler
	// must not perform token exchanges itself.
	LoginLink      func(providerID, authorizationID, redirectURI string) (string, error)
	ConfirmConsent func(providerID, authorizationID, code string) error
	ImportClient   *http.Client
	ExportKey      []byte
	Secrets        keyvault.Retriever
	AcquireToken   func(context.Context, string, string) (string, error)
	// KeyVaultClient overrides ImportClient for the vault leg only, so trusting
	// a sibling emulator's certificate does not loosen API imports.
	KeyVaultClient       *http.Client
	IdentityClientID     string
	IdentityClientSecret string
	mutationMu           sync.Mutex
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
	principal, err := h.Auth.ValidateRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "AuthenticationFailed", err.Error(), "")
		return
	}
	version := r.URL.Query().Get("api-version")
	if authorization, ok := parseAuthorization(r.URL.Path); ok {
		if !authorizationVersions[version] {
			writeError(w, http.StatusBadRequest, "InvalidApiVersionParameter", "The api-version query parameter is invalid or unsupported.", "api-version")
			return
		}
		if !h.authorize(w, r, principal, authorization.Scope) {
			return
		}
		h.authorization(w, r, authorization)
		return
	}
	if !supportedVersions[version] {
		writeError(w, http.StatusBadRequest, "InvalidApiVersionParameter", "The api-version query parameter is invalid or unsupported.", "api-version")
		return
	}
	// The subscription-wide SKU catalogue is a sibling of `service`, not a
	// child of one, so it is answered before the service parser runs.
	if location, ok := parseProviderSKUs(split(r.URL.Path)); ok {
		h.providerSKURoute(w, r, location)
		return
	}
	// Two more subscription-scoped siblings, for the same reason.
	if action, ok := parseServiceProviderAction(split(r.URL.Path)); ok {
		h.serviceProviderAction(w, r, split(r.URL.Path)[1], action)
		return
	}
	parsed, ok := parse(split(r.URL.Path))
	if !ok {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested resource was not found.", r.URL.Path)
		return
	}
	if !h.authorize(w, r, principal, r.URL.Path) {
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
	// A workspace segment is peeled off and recorded as the SCOPE, then
	// dispatch continues on the remaining path. That is the whole mechanism:
	// every family below serves workspace-scoped requests without knowing
	// workspaces exist, because the only thing that changed is the parent ID
	// their resources hang off.
	if equal(parsed.Tail[0], "workspaces") && parsed.Workspace == "" {
		if !h.requireCapability(w, parsed.service().ID(), capabilityWorkspaces) {
			return
		}
		if len(parsed.Tail) == 1 {
			h.workspaceCollection(w, r, parsed)
			return
		}
		if len(parsed.Tail) == 2 {
			h.workspaceResource(w, r, parsed, model.Workspace{ServiceID: parsed.service().ID(), Name: parsed.Tail[1]})
			return
		}
		// No capability check here: the one above already ran for this same
		// service and capability, and nothing between them writes to the store,
		// so a second call can only ever agree with the first. It also cost a
		// redundant service read on every workspace-scoped nested request.
		nested := parsed
		nested.Workspace, nested.Tail = parsed.Tail[1], parsed.Tail[2:]
		// The workspace must exist before anything can be parented to it,
		// otherwise a typo in the path would silently create resources in a
		// scope nobody can address.
		if err := h.requireScope(nested); err != nil {
			h.storeError(w, err, nested.scopeID())
			return
		}
		if serviceOnlyFamilies[strings.ToLower(nested.Tail[0])] {
			writeError(w, http.StatusNotFound, "ResourceNotFound",
				nested.Tail[0]+" is not a workspace-scoped resource in Azure; it belongs to the service.",
				nested.scopeID()+"/"+nested.Tail[0])
			return
		}
		h.dispatch(w, r, nested)
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
	case "caches":
		h.cache(w, r, parsed)
	case "identityProviders":
		h.identityProvider(w, r, parsed)
	case "openidConnectProviders":
		h.openIDConnectProvider(w, r, parsed)
	case "authorizationProviders":
		// Credential manager. Note the neighbour below: authorizationServers is
		// a DIFFERENT resource (the portal console's OAuth2 server), and the
		// two are one word apart.
		h.authorizationProviderRoute(w, r, parsed)
	case "authorizationServers":
		h.authorizationServer(w, r, parsed)
	case "gateways":
		h.gatewayRoute(w, r, parsed)
	case "skus":
		h.skuRoute(w, r, parsed)
	case "regions":
		h.regionRoute(w, r, parsed)
	case "privateEndpointConnections":
		h.privateEndpointConnectionRoute(w, r, parsed)
	case "privateLinkResources":
		h.privateLinkResourceRoute(w, r, parsed)
	case "networkstatus":
		h.networkStatusRoute(w, r, parsed, "")
	case "outboundNetworkDependenciesEndpoints":
		h.outboundNetworkDependenciesRoute(w, r, parsed)
	case "locations":
		// `locations/{name}/networkstatus` is the per-region form. It is the
		// only thing under `locations`, so anything else there is a 404 rather
		// than a hint that more exists.
		if len(parsed.Tail) == 3 && equal(parsed.Tail[2], "networkstatus") {
			h.networkStatusRoute(w, r, parsed, parsed.Tail[1])
			return
		}
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested APIM resource is not implemented in the P0 surface.", r.URL.Path)
	case "documentations":
		h.documentation(w, r, parsed)
	case "schemas":
		h.globalSchema(w, r, parsed)
	case "policyRestrictions":
		h.policyRestriction(w, r, parsed)
	case "getssotoken":
		if len(parsed.Tail) == 1 {
			h.serviceSsoToken(w, r, parsed)
			return
		}
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested APIM resource is not implemented in the P0 surface.", r.URL.Path)
	case "tenant":
		h.tenantAccess(w, r, parsed)
	case "settings":
		h.tenantSettings(w, r, parsed)
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
		h.diagnostic(w, r, parsed, parsed.scopeID(), 1)
	case "products":
		h.product(w, r, parsed)
	case "subscriptions":
		h.subscription(w, r, parsed)
	case "policies":
		if len(parsed.Tail) == 2 && equal(parsed.Tail[1], "policy") {
			// The parent must exist before a policy can hang off it, and which
			// parent that is depends on the scope: a workspace policy belongs
			// to the workspace, not to the service.
			if err := h.requireScope(parsed); err != nil {
				h.storeError(w, err, parsed.scopeID())
				return
			}
			armType := "Microsoft.ApiManagement/service/policies"
			if parsed.Workspace != "" {
				armType = "Microsoft.ApiManagement/service/workspaces/policies"
			}
			h.policyResource(w, r, parsed.scopeID(), armType)
			return
		}
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested APIM resource is not implemented in the P0 surface.", r.URL.Path)
	default:
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested APIM resource is not implemented in the P0 surface.", r.URL.Path)
	}
}

// serviceOnlyFamilies are the resource families Azure exposes at SERVICE scope
// only, so a `/workspaces/{id}/<family>` path must 404 rather than be served.
//
// The peeling above is deliberately family-blind -- that is what let workspaces
// ship without per-family work -- and this is the price of that design: a
// family Azure does NOT put in a workspace is otherwise happily created there,
// parented to the workspace, retrievable, and absent from Azure. That is the
// leniency direction, which has no local symptom: the flow works here and 404s
// the first time it runs against a real tenant.
//
// The list is derived from `@azure/arm-apimanagement@10.0.0`, which publishes a
// separate `Workspace*` operation group for every family Azure genuinely scopes
// to a workspace (WorkspaceApi, WorkspaceBackend, WorkspaceCertificate,
// WorkspaceNamedValue, WorkspaceProduct, WorkspaceSubscription, WorkspaceTag,
// WorkspaceGroup, WorkspaceLogger, WorkspaceDiagnostic, WorkspacePolicy,
// WorkspacePolicyFragment, WorkspaceApiVersionSet, WorkspaceGlobalSchema,
// WorkspaceNotification). A family below has no such group.
//
// `users` is the one worth explaining: there IS a `WorkspaceGroupUser`, but it
// is a MEMBERSHIP link, not user CRUD. Users are a service-level directory that
// a workspace group draws members from, so the directory itself is not
// workspace-scoped.
//
// Being a snapshot of one SDK version, this is evidence rather than proof: if a
// later SDK adds a Workspace* group for one of these, delete the row.
var serviceOnlyFamilies = map[string]bool{
	"caches":                 true,
	"identityproviders":      true,
	"openidconnectproviders": true,
	"authorizationproviders": true,
	"authorizationservers":   true,
	"documentations":         true,
	"gateways":               true,
	"users":                  true,
	// Networking belongs to the service, never to a workspace inside it.
	"privateendpointconnections":           true,
	"privatelinkresources":                 true,
	"networkstatus":                        true,
	"outboundnetworkdependenciesendpoints": true,
	"locations":                            true,
	"skus":                                 true,
	"regions":                              true,
	// The tenant access configurations and the public settings belong to the
	// service: the SDK publishes no Workspace* group for either.
	"tenant":   true,
	"settings": true,
	// A policy RESTRICTION is service-wide. There are Workspace* groups for
	// every kind of policy DOCUMENT (WorkspacePolicy, WorkspaceApiPolicy,
	// WorkspaceProductPolicy, WorkspacePolicyFragment) and none for this.
	"policyrestrictions": true,
	// The publisher-portal SSO token is issued for the service.
	"getssotoken": true,
}

type route struct {
	SubscriptionID, ResourceGroup, ServiceName string
	// Workspace is set when the path carried a `/workspaces/{id}` segment. It
	// is a SCOPE, not a resource kind: every family Azure exposes under a
	// workspace is the same family it exposes under the service, parented
	// differently. Modelling it as a scope is what lets one set of handlers
	// serve both, and the store's exact parent matching is what keeps the two
	// sets of resources from leaking into each other's listings.
	Workspace string
	Tail      []string
}

// service is the ARM service this route addresses.
func (rt route) service() model.Service {
	return model.Service{SubscriptionID: rt.SubscriptionID, ResourceGroup: rt.ResourceGroup, Name: rt.ServiceName}
}

// scopeID is the parent every resource under this route belongs to: the
// service, or a workspace within it.
func (rt route) scopeID() string {
	if rt.Workspace == "" {
		return rt.service().ID()
	}
	return rt.service().ID() + "/workspaces/" + rt.Workspace
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

func cleanResourceDocument(document map[string]any) {
	delete(document, "id")
	delete(document, "name")
	delete(document, "type")
	delete(document, "etag")
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

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
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
	if code == "ValidationError" && target != "" {
		errorValue["details"] = []map[string]any{{"code": code, "message": message, "target": target}}
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

// requireScope reports whether the route's parent exists: the workspace when
// the path named one, otherwise the service.
func (h *Handler) requireScope(rt route) error {
	if rt.Workspace != "" {
		_, err := h.Store.GetWorkspace(rt.scopeID())
		return err
	}
	_, err := h.Store.GetService(rt.service().ID())
	return err
}

// authorizationProviderRoute dispatches the credential-manager resource tree:
// providers, the credentials under them, and each credential's access policies.
func (h *Handler) authorizationProviderRoute(w http.ResponseWriter, r *http.Request, rt route) {
	serviceID := rt.service().ID()
	switch len(rt.Tail) {
	case 1:
		h.authorizationProviderCollection(w, r, serviceID)
	case 2:
		h.authorizationProviderResource(w, r, model.AuthorizationProvider{ServiceID: serviceID, Name: rt.Tail[1]})
	case 3, 4, 5, 6:
		providerID := serviceID + "/authorizationProviders/" + rt.Tail[1]
		if !equal(rt.Tail[2], "authorizations") {
			writeError(w, http.StatusNotFound, "ResourceNotFound", "The resource was not found.", providerID)
			return
		}
		h.authorizationRoute(w, r, rt, providerID)
	default:
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The resource was not found.", serviceID)
	}
}

func (h *Handler) authorizationRoute(w http.ResponseWriter, r *http.Request, rt route, providerID string) {
	// The provider must exist before anything beneath it is addressable,
	// otherwise a typo in the provider name silently creates a credential under
	// a provider nobody configured.
	if _, err := h.Store.GetAuthorizationProvider(providerID); err != nil {
		h.storeError(w, err, providerID)
		return
	}
	switch len(rt.Tail) {
	case 3:
		h.authorizationCollection(w, r, providerID)
		return
	case 4:
		h.authorizationResource(w, r, model.Authorization{ProviderID: providerID, Name: rt.Tail[3]})
		return
	}
	authorizationID := providerID + "/authorizations/" + rt.Tail[3]
	if len(rt.Tail) == 5 && !equal(rt.Tail[4], "accessPolicies") {
		h.authorizationAction(w, r, model.Authorization{ProviderID: providerID, Name: rt.Tail[3]}, rt.Tail[4])
		return
	}
	if len(rt.Tail) == 5 && equal(rt.Tail[4], "accessPolicies") {
		if _, err := h.Store.GetAuthorization(authorizationID); err != nil {
			h.storeError(w, err, authorizationID)
			return
		}
		h.accessPolicyCollection(w, r, authorizationID)
		return
	}
	if len(rt.Tail) == 6 && equal(rt.Tail[4], "accessPolicies") {
		if _, err := h.Store.GetAuthorization(authorizationID); err != nil {
			h.storeError(w, err, authorizationID)
			return
		}
		h.accessPolicyResource(w, r, model.AuthorizationAccessPolicy{AuthorizationID: authorizationID, Name: rt.Tail[5]})
		return
	}
	writeError(w, http.StatusNotFound, "ResourceNotFound", "The resource was not found.", authorizationID)
}
