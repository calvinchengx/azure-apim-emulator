// Package gateway compiles APIM resources into immutable request snapshots.
package gateway

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	certutil "github.com/calvinchengx/azure-apim-emulator/internal/certificate"
	"github.com/calvinchengx/azure-apim-emulator/internal/expression"
	"github.com/calvinchengx/azure-apim-emulator/internal/graphql"
	"github.com/calvinchengx/azure-apim-emulator/internal/grpcapi"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
	soapc "github.com/calvinchengx/azure-apim-emulator/internal/soap"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
	"golang.org/x/net/websocket"
)

// Snapshot is the complete active gateway configuration.
type Snapshot struct {
	Services map[string]*Service
}

// SnapshotSummary returns a JSON-friendly view of the active gateway bundle.
func (r *Runtime) SnapshotSummary() map[string]any {
	snapshot := r.current.Load()
	services := make([]map[string]any, 0, len(snapshot.Services))
	for _, service := range snapshot.Services {
		routes := make([]map[string]any, 0, len(service.Routes))
		for _, route := range service.Routes {
			routes = append(routes, map[string]any{"api": route.API.ID(), "path": route.API.Path, "operations": len(route.Operations)})
		}
		services = append(services, map[string]any{"name": service.Name, "hostnames": service.Hostnames, "routes": routes})
	}
	sort.Slice(services, func(left, right int) bool { return services[left]["name"].(string) < services[right]["name"].(string) })
	return map[string]any{"services": services}
}

// Service is compiled runtime state for one APIM service.
type Service struct {
	Name                  string
	Location              string
	Hostnames             map[string]bool
	PublicNetworkDisabled bool
	Routes                []*Route
	Backends              map[string]model.Backend
	Certificates          map[string]model.Certificate
	Diagnostics           []model.Diagnostic
	Products              map[string]model.Product
	Subscriptions         map[string]model.Subscription
}

// Route is a compiled API route.
type Route struct {
	API               model.API
	VersionSet        *model.APIVersionSet
	Operations        []model.Operation
	Plan              policy.Plan
	OperationPlans    map[string]policy.Plan
	SubscriptionPlans map[string]policy.Plan
	AcceptedKeys      map[string]bool
	Diagnostics       []model.Diagnostic
	// GraphQL is the compiled schema of a GraphQL API, nil for every other API
	// type. Its presence is what puts a request on the GraphQL path, so an API
	// whose schema failed to compile stays a plain HTTP proxy rather than
	// half-serving GraphQL.
	GraphQL *graphql.Schema
	// GRPC is the compiled protobuf schema of a gRPC API, nil for every other
	// API type.
	GRPC *grpcapi.Schema
	// SOAP is the compiled WSDL of a SOAP API, nil for every other API type.
	SOAP *soapc.Schema
	// Resolvers make the API SYNTHETIC: present means fields are produced by
	// resolvers and no GraphQL backend is contacted. Empty means pass-through.
	// The two are mutually exclusive by construction rather than by a flag,
	// because an API cannot be half of each.
	Resolvers map[string]compiledResolver
}

// Runtime atomically publishes snapshots and serves gateway traffic.
type Runtime struct {
	defaultService       string
	client               *http.Client
	current              atomic.Pointer[Snapshot]
	traceMu              sync.RWMutex
	traces               map[string]Trace
	traceOrder           []string
	eventStore           atomic.Pointer[store.Store]
	breakerMu            sync.Mutex
	breakers             map[string]circuitState
	credentials          *credentialCache
	policyTokenValidator func(string) error
	policySendRequest    func(*http.Request) (*http.Response, error)
	faultMu              sync.Mutex
	faults               map[string]Fault
	rateMu               sync.Mutex
	rateWindows          map[string][]time.Time
	bandwidthWindows     map[string][]bandwidthStamp
	cacheMu              sync.Mutex
	cache                map[string]cacheEntry
	valueCache           map[string]valueCacheEntry
	concurrencyMu        sync.Mutex
	concurrency          map[string]chan struct{}
}

type bandwidthStamp struct {
	at    time.Time
	bytes int64
}

type cacheEntry struct {
	status  int
	headers http.Header
	body    string
	expires time.Time
}

type valueCacheEntry struct {
	value   string
	expires time.Time
}

// Fault is a deterministic operator-injected backend outcome.
type Fault struct {
	Status    int    `json:"status,omitempty"`
	DelayMS   int    `json:"delayMs,omitempty"`
	Error     bool   `json:"error,omitempty"`
	Remaining int    `json:"remaining,omitempty"`
	Body      string `json:"body,omitempty"`
}

type circuitState struct {
	failures    []time.Time
	openedUntil time.Time
}

type circuitRule struct {
	count        int
	interval     time.Duration
	tripDuration time.Duration
	statusMin    int
	statusMax    int
}

// Trace is a bounded structured record of one opted-in gateway request.
type Trace struct {
	ID      string       `json:"id"`
	Method  string       `json:"method"`
	Path    string       `json:"path"`
	Service string       `json:"service"`
	API     string       `json:"api,omitempty"`
	Status  int          `json:"status"`
	Events  []TraceEvent `json:"events"`
}

// TraceEvent records a gateway pipeline phase and optional detail.
type TraceEvent struct {
	Phase  string `json:"phase"`
	Detail string `json:"detail,omitempty"`
}

// New creates an empty gateway runtime.
func New(defaultService string, client *http.Client) *Runtime {
	if client == nil {
		client = http.DefaultClient
	}
	r := &Runtime{defaultService: defaultService, client: client, policySendRequest: client.Do, traces: map[string]Trace{}, breakers: map[string]circuitState{}, faults: map[string]Fault{}, rateWindows: map[string][]time.Time{}, bandwidthWindows: map[string][]bandwidthStamp{}, cache: map[string]cacheEntry{}, valueCache: map[string]valueCacheEntry{}, concurrency: map[string]chan struct{}{}, credentials: newCredentialCache()}
	r.current.Store(&Snapshot{Services: map[string]*Service{}})
	return r
}

// SetPolicyTokenValidator configures the validator used by gateway JWT policies.
func (r *Runtime) SetPolicyTokenValidator(validate func(string) error) {
	r.policyTokenValidator = validate
}

func (r *Runtime) rateLimit(key string, calls int, period time.Duration) bool {
	now := time.Now()
	r.rateMu.Lock()
	defer r.rateMu.Unlock()
	window := r.rateWindows[key]
	cutoff := now.Add(-period)
	kept := window[:0]
	for _, stamp := range window {
		if stamp.After(cutoff) {
			kept = append(kept, stamp)
		}
	}
	if len(kept) >= calls {
		r.rateWindows[key] = kept
		return true
	}
	r.rateWindows[key] = append(kept, now)
	return false
}

func (r *Runtime) bandwidthLimit(key string, add, budget int64, period time.Duration) bool {
	if add < 0 {
		add = 0
	}
	now := time.Now()
	r.rateMu.Lock()
	defer r.rateMu.Unlock()
	window := r.bandwidthWindows[key]
	cutoff := now.Add(-period)
	kept := window[:0]
	var total int64
	for _, stamp := range window {
		if stamp.at.After(cutoff) {
			kept = append(kept, stamp)
			total += stamp.bytes
		}
	}
	if total+add > budget {
		r.bandwidthWindows[key] = kept
		return true
	}
	r.bandwidthWindows[key] = append(kept, bandwidthStamp{at: now, bytes: add})
	return false
}

func (r *Runtime) acquireConcurrency(key string, max int) func() {
	r.concurrencyMu.Lock()
	semaphore := r.concurrency[key]
	if semaphore == nil || cap(semaphore) != max {
		semaphore = make(chan struct{}, max)
		r.concurrency[key] = semaphore
	}
	select {
	case semaphore <- struct{}{}:
		r.concurrencyMu.Unlock()
		var once sync.Once
		return func() {
			once.Do(func() { <-semaphore })
		}
	default:
		r.concurrencyMu.Unlock()
		return nil
	}
}

func (r *Runtime) cacheGet(key string) (int, http.Header, string, bool) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	entry, ok := r.cache[key]
	if !ok {
		return 0, nil, "", false
	}
	if !entry.expires.After(time.Now()) {
		delete(r.cache, key)
		return 0, nil, "", false
	}
	return entry.status, entry.headers.Clone(), entry.body, true
}

func (r *Runtime) cacheSet(key string, status int, headers http.Header, body string, duration time.Duration) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	r.cache[key] = cacheEntry{status: status, headers: headers.Clone(), body: body, expires: time.Now().Add(duration)}
}

func (r *Runtime) valueCacheGet(key string) (string, bool) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	entry, ok := r.valueCache[key]
	if !ok || !entry.expires.After(time.Now()) {
		if ok {
			delete(r.valueCache, key)
		}
		return "", false
	}
	return entry.value, true
}

func (r *Runtime) valueCacheSet(key, value string, duration time.Duration) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	r.valueCache[key] = valueCacheEntry{value: value, expires: time.Now().Add(duration)}
}

func (r *Runtime) valueCacheRemove(key string) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	delete(r.valueCache, key)
}

func faultKey(service, backend string) string {
	return strings.ToLower(strings.TrimSpace(service) + "/" + strings.TrimSpace(backend))
}

// SetFault installs a fault; an empty fault clears it.
func (r *Runtime) SetFault(service, backend string, fault Fault) {
	r.faultMu.Lock()
	defer r.faultMu.Unlock()
	key := faultKey(service, backend)
	if fault.Status == 0 && fault.DelayMS == 0 && !fault.Error && fault.Body == "" {
		delete(r.faults, key)
		return
	}
	r.faults[key] = fault
}

func (r *Runtime) FaultsSnapshot() map[string]Fault {
	r.faultMu.Lock()
	defer r.faultMu.Unlock()
	result := make(map[string]Fault, len(r.faults))
	for key, fault := range r.faults {
		result[key] = fault
	}
	return result
}

func (r *Runtime) takeFault(service, backend string) (Fault, bool) {
	r.faultMu.Lock()
	defer r.faultMu.Unlock()
	key := faultKey(service, backend)
	fault, ok := r.faults[key]
	if !ok {
		key = faultKey(service, "*")
		fault, ok = r.faults[key]
	}
	if !ok {
		return Fault{}, false
	}
	if fault.Remaining > 0 {
		fault.Remaining--
		if fault.Remaining == 0 {
			delete(r.faults, key)
		} else {
			r.faults[key] = fault
		}
	}
	return fault, true
}

// Activate compiles all stored resources and atomically publishes them.
func (r *Runtime) Activate(st *store.Store, strict bool) error {
	services, apis, operations, products, links, subscriptions, policies, err := st.RuntimeData()
	if err != nil {
		return err
	}
	versionSets := map[string]*model.APIVersionSet{}
	namedValues := map[string]map[string]string{}
	backends := map[string]map[string]model.Backend{}
	certificates := map[string]map[string]model.Certificate{}
	fragments := map[string]map[string]string{}
	diagnostics := map[string][]model.Diagnostic{}
	for _, service := range services {
		values, err := st.ListAPIVersionSets(service.ID())
		if err != nil {
			return err
		}
		for index := range values {
			value := values[index]
			versionSets[strings.ToLower(value.ID())] = &value
		}
		serviceValues, err := st.ListNamedValues(service.ID())
		if err != nil {
			return err
		}
		namedValues[strings.ToLower(service.ID())] = map[string]string{}
		for _, value := range serviceValues {
			namedValues[strings.ToLower(service.ID())][strings.ToLower(value.DisplayName)] = value.Value
		}
		serviceBackends, err := st.ListBackends(service.ID())
		if err != nil {
			return err
		}
		backends[strings.ToLower(service.ID())] = map[string]model.Backend{}
		for _, value := range serviceBackends {
			backends[strings.ToLower(service.ID())][strings.ToLower(value.Name)] = value
		}
		serviceCertificates, err := st.ListCertificates(service.ID())
		if err != nil {
			return err
		}
		certificates[strings.ToLower(service.ID())] = map[string]model.Certificate{}
		for _, value := range serviceCertificates {
			certificates[strings.ToLower(service.ID())][strings.ToLower(value.ID())] = value
			certificates[strings.ToLower(service.ID())][strings.ToLower(value.Name)] = value
		}
		if err := validateBackendCertificates(backends[strings.ToLower(service.ID())], certificates[strings.ToLower(service.ID())]); err != nil {
			return err
		}
		serviceFragments, err := st.ListPolicyFragments(service.ID())
		if err != nil {
			return err
		}
		fragments[strings.ToLower(service.ID())] = map[string]string{}
		for _, value := range serviceFragments {
			fragments[strings.ToLower(service.ID())][strings.ToLower(value.Name)] = value.Value
		}
		serviceDiagnostics, err := st.ListServiceDiagnostics(service.ID())
		if err != nil {
			return err
		}
		for _, diagnostic := range serviceDiagnostics {
			diagnostics[strings.ToLower(diagnostic.ScopeID)] = append(diagnostics[strings.ToLower(diagnostic.ScopeID)], diagnostic)
		}
	}
	policyByScope := map[string]policy.Plan{}
	for _, item := range policies {
		// A resolver's policy is an <http-data-source>, not a <policies>
		// document, and it is compiled per resolver in graphQLResolversFor.
		// Feeding it to the plan compiler would fail every activation for a
		// service that has any synthetic GraphQL API.
		if isResolverScope(item.ScopeID) {
			continue
		}
		resolved, err := resolveNamedValues(item.Value, namedValues[strings.ToLower(serviceIDFromScope(item.ScopeID))])
		if err != nil {
			return fmt.Errorf("compile policy %s: %w", item.ScopeID, err)
		}
		plan, err := policy.CompileWithFragments(resolved, fragments[strings.ToLower(serviceIDFromScope(item.ScopeID))], strict)
		if err != nil {
			return fmt.Errorf("compile policy %s: %w", item.ScopeID, err)
		}
		if err := resolveBackendReferences(&plan, backends[strings.ToLower(serviceIDFromScope(item.ScopeID))]); err != nil {
			return fmt.Errorf("compile policy %s: %w", item.ScopeID, err)
		}
		policyByScope[strings.ToLower(item.ScopeID)] = plan
	}
	operationsByAPI := map[string][]model.Operation{}
	for _, operation := range operations {
		operationsByAPI[strings.ToLower(operation.APIID)] = append(operationsByAPI[strings.ToLower(operation.APIID)], operation)
	}
	keysByAPI := map[string]map[string]bool{}
	for _, api := range apis {
		keysByAPI[strings.ToLower(api.ID())] = map[string]bool{}
	}
	for _, subscription := range subscriptions {
		if !strings.EqualFold(subscription.State, "active") {
			continue
		}
		for _, api := range apis {
			allowed := strings.EqualFold(subscription.Scope, api.ID()) || strings.EqualFold(subscription.Scope, logicalAPIID(api.ID())) || strings.EqualFold(subscription.Scope, api.ServiceID)
			if linkedAPIs := links[subscription.Scope]; !allowed {
				for _, linkedAPI := range linkedAPIs {
					if strings.EqualFold(linkedAPI, api.ID()) || strings.EqualFold(linkedAPI, logicalAPIID(api.ID())) {
						allowed = true
						break
					}
				}
			}
			if allowed {
				keysByAPI[strings.ToLower(api.ID())][subscription.PrimaryKey] = true
				keysByAPI[strings.ToLower(api.ID())][subscription.SecondaryKey] = true
			}
		}
	}
	snapshot := &Snapshot{Services: map[string]*Service{}}
	for _, item := range services {
		snapshot.Services[strings.ToLower(item.Name)] = &Service{Name: item.Name, Location: item.Location, Hostnames: customHostnames(item.Document), PublicNetworkDisabled: !publicNetworkAccess(item.Document), Backends: backends[strings.ToLower(item.ID())], Certificates: certificates[strings.ToLower(item.ID())], Diagnostics: diagnostics[strings.ToLower(item.ID())], Products: map[string]model.Product{}, Subscriptions: map[string]model.Subscription{}}
	}
	indexServiceIdentities(snapshot.Services, products, subscriptions)
	for _, api := range apis {
		if !api.IsCurrent {
			continue
		}
		serviceName := serviceNameFromID(api.ServiceID)
		service := snapshot.Services[strings.ToLower(serviceName)]
		if service == nil {
			return fmt.Errorf("API %s references missing service", api.ID())
		}
		var versionSet *model.APIVersionSet
		if api.VersionSetID != "" {
			versionSet = versionSets[strings.ToLower(api.VersionSetID)]
			if versionSet == nil {
				return fmt.Errorf("API %s references missing version set", api.ID())
			}
		}
		plan := policyByScope[strings.ToLower(api.ID())]
		servicePlan, hasServicePlan := policyByScope[strings.ToLower(api.ServiceID)]
		if _, defined := policyByScope[strings.ToLower(api.ID())]; !defined {
			plan = servicePlan
		} else if hasServicePlan {
			plan = composeInheritedPlan(plan, servicePlan)
		}
		operationList := operationsByAPI[strings.ToLower(api.ID())]
		operationPlans := map[string]policy.Plan{}
		for _, operation := range operationList {
			operationPlan := plan
			operationID := operation.APIID + "/operations/" + operation.Name
			if operationPolicy, defined := policyByScope[strings.ToLower(operationID)]; defined {
				operationPlan = composeInheritedPlan(operationPolicy, plan)
			}
			operationPlans[strings.ToLower(operationID)] = operationPlan
		}
		subscriptionPlans := map[string]policy.Plan{}
		for _, subscription := range subscriptions {
			if !strings.EqualFold(subscription.State, "active") || !strings.HasPrefix(strings.ToLower(subscription.Scope), strings.ToLower(api.ServiceID)+"/products/") {
				continue
			}
			linked := false
			for _, linkedAPI := range links[subscription.Scope] {
				if strings.EqualFold(linkedAPI, api.ID()) || strings.EqualFold(linkedAPI, logicalAPIID(api.ID())) {
					linked = true
					break
				}
			}
			if !linked {
				continue
			}
			if productPlan, defined := policyByScope[strings.ToLower(subscription.Scope)]; defined {
				subscriptionPlans[strings.ToLower(subscription.PrimaryKey)] = productPlan
				subscriptionPlans[strings.ToLower(subscription.SecondaryKey)] = productPlan
			}
		}
		schema, err := graphQLSchemaFor(st, api)
		if err != nil {
			// strict is the management-plane path, where a caller is waiting on
			// the result of its own import and must be told it was rejected.
			// Non-strict is startup replay of already-accepted state, where
			// failing the whole activation over one bad API would take every
			// other API down with it.
			if strict {
				return err
			}
			schema = nil
		}
		soapSchema, err := soapSchemaFor(st, api)
		if err != nil {
			if strict {
				return err
			}
			soapSchema = nil
		}
		grpcSchema, err := grpcSchemaFor(st, api)
		if err != nil {
			if strict {
				return err
			}
			grpcSchema = nil
		}
		resolvers, err := graphQLResolversFor(st, api, schema)
		if err != nil {
			if strict {
				return err
			}
			resolvers = nil
		}
		service.Routes = append(service.Routes, &Route{API: api, VersionSet: versionSet, Operations: operationList, OperationPlans: operationPlans, SubscriptionPlans: subscriptionPlans, Plan: plan, AcceptedKeys: keysByAPI[strings.ToLower(api.ID())], Diagnostics: diagnostics[strings.ToLower(api.ID())], GraphQL: schema, Resolvers: resolvers, GRPC: grpcSchema, SOAP: soapSchema})
	}
	for _, service := range snapshot.Services {
		sort.SliceStable(service.Routes, func(i, j int) bool { return len(service.Routes[i].API.Path) > len(service.Routes[j].API.Path) })
	}
	r.current.Store(snapshot)
	r.eventStore.Store(st)
	return nil
}

func composeInheritedPlan(child, parent policy.Plan) policy.Plan {
	return policy.Plan{
		Inbound:  composeInheritedActions(child.Inbound, parent.Inbound),
		Backend:  composeInheritedActions(child.Backend, parent.Backend),
		Outbound: composeInheritedActions(child.Outbound, parent.Outbound),
		OnError:  composeInheritedActions(child.OnError, parent.OnError),
	}
}

func composeInheritedActions(child, parent []policy.Action) []policy.Action {
	result := make([]policy.Action, 0, len(child)+len(parent))
	for _, action := range child {
		if action.Kind == policy.ActionBase {
			result = append(result, parent...)
		} else {
			result = append(result, action)
		}
	}
	return result
}

func mergeProductPlan(product, child policy.Plan) policy.Plan {
	return policy.Plan{
		Inbound:  mergeProductActions(product.Inbound, child.Inbound),
		Backend:  mergeProductActions(product.Backend, child.Backend),
		Outbound: mergeProductActions(product.Outbound, child.Outbound),
		OnError:  mergeProductActions(product.OnError, child.OnError),
	}
}

func mergeProductActions(product, child []policy.Action) []policy.Action {
	result := make([]policy.Action, 0, len(product)+len(child))
	base := false
	for _, action := range product {
		if action.Kind == policy.ActionBase {
			result = append(result, child...)
			base = true
		} else {
			result = append(result, action)
		}
	}
	if !base {
		result = append(result, child...)
	}
	return result
}

func resolveBackendReferences(plan *policy.Plan, backends map[string]model.Backend) error {
	sections := []*[]policy.Action{&plan.Inbound, &plan.Backend, &plan.Outbound, &plan.OnError}
	for _, section := range sections {
		for index := range *section {
			action := &(*section)[index]
			if action.Kind != policy.ActionSetBackend || action.BackendID == "" {
				continue
			}
			backend, ok := backends[strings.ToLower(action.BackendID)]
			if !ok {
				return fmt.Errorf("backend %q was not found", action.BackendID)
			}
			action.Value = backend.URL
		}
	}
	return nil
}

var namedValueReference = regexp.MustCompile(`\{\{([^{}]+)\}\}`)

func resolveNamedValues(source string, values map[string]string) (string, error) {
	var resolveErr error
	resolved := namedValueReference.ReplaceAllStringFunc(source, func(reference string) string {
		name := strings.TrimSpace(reference[2 : len(reference)-2])
		value, ok := values[strings.ToLower(name)]
		if !ok {
			resolveErr = fmt.Errorf("named value %q was not found", name)
			return reference
		}
		return html.EscapeString(value)
	})
	return resolved, resolveErr
}

func serviceIDFromScope(id string) string {
	lower := strings.ToLower(id)
	for _, child := range []string{"/apis/", "/products/", "/subscriptions/", "/namedvalues/"} {
		if index := strings.Index(lower, child); index >= 0 {
			return id[:index]
		}
	}
	return id
}

func serviceNameFromID(id string) string {
	parts := strings.Split(strings.Trim(id, "/"), "/")
	for index := 0; index+1 < len(parts); index++ {
		if strings.EqualFold(parts[index], "service") {
			return parts[index+1]
		}
	}
	return ""
}

func indexServiceIdentities(services map[string]*Service, products []model.Product, subscriptions []model.Subscription) {
	for _, product := range products {
		service := services[strings.ToLower(serviceNameFromID(product.ServiceID))]
		if service == nil || service.Products == nil {
			continue
		}
		service.Products[strings.ToLower(product.ID())] = product
	}
	for _, subscription := range subscriptions {
		service := services[strings.ToLower(serviceNameFromID(subscription.ServiceID))]
		if service == nil || service.Subscriptions == nil {
			continue
		}
		if subscription.PrimaryKey != "" {
			service.Subscriptions[strings.ToLower(subscription.PrimaryKey)] = subscription
		}
		if subscription.SecondaryKey != "" {
			service.Subscriptions[strings.ToLower(subscription.SecondaryKey)] = subscription
		}
	}
}

func displayName(display, name string) string {
	if display != "" {
		return display
	}
	return name
}

func bindRequestContext(service *Service, route *Route, operation model.Operation, req *http.Request) (*expression.ApiContext, *expression.OperationContext, *expression.NamedContext, *expression.NamedContext, *expression.NamedContext, *expression.DeploymentContext) {
	var api *expression.ApiContext
	if route != nil {
		api = &expression.ApiContext{Id: route.API.Name, Name: displayName(route.API.DisplayName, route.API.Name), Path: strings.Trim(route.API.Path, "/")}
	}
	operationCtx := &expression.OperationContext{Id: operation.Name, Name: displayName(operation.DisplayName, operation.Name), Method: operation.Method, UrlTemplate: operation.URLTemplate}
	var product, subscription, user *expression.NamedContext
	var deployment *expression.DeploymentContext
	if service != nil {
		deployment = &expression.DeploymentContext{ServiceName: service.Name, Region: service.Location}
		if req != nil && service.Subscriptions != nil {
			if matched, ok := service.Subscriptions[strings.ToLower(subscriptionKey(req))]; ok {
				subscription = &expression.NamedContext{Id: matched.Name, Name: displayName(matched.DisplayName, matched.Name)}
				if service.Products != nil {
					if linked, ok := service.Products[strings.ToLower(matched.Scope)]; ok {
						product = &expression.NamedContext{Id: linked.Name, Name: displayName(linked.DisplayName, linked.Name)}
					}
				}
			}
		}
	}
	return api, operationCtx, product, subscription, user, deployment
}

func logicalAPIID(id string) string {
	index := strings.LastIndex(strings.ToLower(id), ";rev=")
	if index < 0 {
		return id
	}
	return id[:index]
}

// ServeHTTP handles managed gateway requests.
func (r *Runtime) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	trace, tracedWriter := r.beginTrace(w, req)
	if trace != nil {
		w = tracedWriter
		defer r.finishTrace(trace, tracedWriter)
	}
	snapshot := r.current.Load()
	serviceName := serviceForHost(snapshot, req.Host, r.defaultService)
	traceEvent(trace, "ingress", serviceName)
	service := snapshot.Services[strings.ToLower(serviceName)]
	if service == nil {
		gatewayError(w, http.StatusNotFound, "ServiceNotFound", "API Management service was not found.")
		return
	}
	if service.PublicNetworkDisabled {
		gatewayError(w, http.StatusForbidden, "PublicNetworkAccessDisabled", "Public network access is disabled for this service.")
		return
	}
	route, relative := matchRoute(service.Routes, req)
	if route == nil {
		gatewayError(w, http.StatusNotFound, "OperationNotFound", "Unable to match incoming request to an operation.")
		return
	}
	diagnosticStart := time.Now()
	reqLimit, respLimit := diagnosticBodyLimits(append(append([]model.Diagnostic{}, service.Diagnostics...), route.Diagnostics...))
	diagnosticOutput := &diagnosticWriter{ResponseWriter: w, bodyLimit: respLimit, requestBody: snapshotRequestBody(req, reqLimit)}
	w = diagnosticOutput
	defer r.emitDiagnostics(req, service, route, diagnosticOutput, diagnosticStart)
	if trace != nil {
		trace.API = route.API.ID()
	}
	traceEvent(trace, "route", route.API.Path)
	operation, matched := matchOperationValue(route.Operations, req.Method, relative)
	if !matched {
		// A GraphQL API is one endpoint, not a set of REST operations, so there
		// is nothing for the matcher to match. The schema decides what is valid
		// here, and it does so per GraphQL field rather than per URL.
		if route.GraphQL == nil && route.GRPC == nil && route.SOAP == nil {
			gatewayError(w, http.StatusNotFound, "OperationNotFound", "Unable to match incoming request to an operation.")
			return
		}
		name, display := graphQLAPIType, "GraphQL"
		switch {
		case route.GRPC != nil:
			name, display = grpcAPIType, "gRPC"
		case route.SOAP != nil:
			name, display = soapAPIType, "SOAP"
		}
		operation = model.Operation{APIID: route.API.ID(), Name: name, DisplayName: display, Method: req.Method, URLTemplate: relative}
	}
	activePlan := route.Plan
	operationID := operation.APIID + "/operations/" + operation.Name
	if operationPlan, ok := route.OperationPlans[strings.ToLower(operationID)]; ok {
		activePlan = operationPlan
	}
	if route.API.SubscriptionRequired && !validSubscription(req, route.AcceptedKeys) {
		message := "Access denied due to missing subscription key. Make sure to include subscription key when making requests to an API."
		if subscriptionKey(req) != "" {
			message = "Access denied due to invalid subscription key. Check that the key is active and belongs to the requested API."
		}
		gatewayError(w, http.StatusUnauthorized, "SubscriptionKeyInvalid", message)
		return
	}
	if productPlan, ok := route.SubscriptionPlans[strings.ToLower(subscriptionKey(req))]; ok {
		activePlan = mergeProductPlan(productPlan, activePlan)
	}
	cacheKey := service.Name + ":" + route.API.ID() + ":" + req.Method + ":" + req.URL.RequestURI()
	apiCtx, operationCtx, productCtx, subscriptionCtx, userCtx, deploymentCtx := bindRequestContext(service, route, operation, req)
	state := &policy.State{Request: req, BackendURL: route.API.ServiceURL, Path: relative, Headers: make(http.Header), ValidateToken: r.policyTokenValidator, SendRequest: r.policySendRequest, FetchCredential: r.credentialFetcher(req, route.API.ServiceID), Trace: func(phase, detail string) { traceEvent(trace, phase, detail) }, RateLimit: r.rateLimit, BandwidthLimit: r.bandwidthLimit, AcquireConcurrency: r.acquireConcurrency, CacheGet: r.cacheGet, CacheSet: r.cacheSet, ValueCacheGet: r.valueCacheGet, ValueCacheSet: r.valueCacheSet, ValueCacheRemove: r.valueCacheRemove, CacheKey: cacheKey, Api: apiCtx, Operation: operationCtx, Product: productCtx, Subscription: subscriptionCtx, User: userCtx, Deployment: deploymentCtx}
	defer func() {
		for index := len(state.ConcurrencyReleases) - 1; index >= 0; index-- {
			state.ConcurrencyReleases[index]()
		}
	}()
	traceEvent(trace, "inbound", "")
	if err := policy.Execute(activePlan.Inbound, state); err != nil {
		r.policyFailure(w, req, activePlan, state, err)
		return
	}
	if state.Returned {
		writePolicyResponse(w, state)
		return
	}
	traceEvent(trace, "backend", state.BackendURL)
	if err := policy.Execute(activePlan.Backend, state); err != nil {
		r.policyFailure(w, req, activePlan, state, err)
		return
	}
	if state.Returned {
		writePolicyResponse(w, state)
		return
	}
	if isWebSocketRequest(req) {
		r.serveWebSocket(w, req, state.BackendURL, state.Path)
		return
	}
	if route.SOAP != nil && isSOAPRequest(req) {
		r.serveSOAP(w, req, service, route, state, activePlan)
		return
	}
	if route.GRPC != nil && isGRPCRequest(req) {
		r.serveGRPC(w, req, service, route, state, activePlan)
		return
	}
	if route.GraphQL != nil {
		r.serveGraphQL(w, req, service, route, state, activePlan)
		return
	}
	client, err := backendHTTPClient(r.client, service, state.BackendID)
	if err != nil {
		r.policyFailure(w, req, activePlan, state, err)
		return
	}
	if r.circuitOpen(service, state.BackendID, time.Now()) {
		r.policyFailure(w, req, activePlan, state, fmt.Errorf("backend circuit breaker is open"))
		return
	}
	if fault, ok := r.takeFault(service.Name, state.BackendID); ok {
		r.serveInjectedFault(w, req, activePlan, state, fault)
		return
	}
	response, err := forwardWithRetry(client, req, state.BackendURL, state.Path, activePlan.Backend)
	r.recordCircuit(service, state.BackendID, response, err, time.Now())
	if err != nil {
		r.policyFailure(w, req, activePlan, state, fmt.Errorf("backend request failed: %w", err))
		return
	}
	defer response.Body.Close()
	state.Response = response
	traceEvent(trace, "outbound", "")
	if err := policy.Execute(activePlan.Outbound, state); err != nil {
		r.policyFailure(w, req, activePlan, state, err)
		return
	}
	if state.Returned {
		writePolicyResponse(w, state)
		return
	}
	writeForwardedResponse(w, response, state)
}

func (r *Runtime) serveInjectedFault(w http.ResponseWriter, req *http.Request, plan policy.Plan, state *policy.State, fault Fault) {
	if fault.DelayMS > 0 {
		time.Sleep(time.Duration(fault.DelayMS) * time.Millisecond)
	}
	if fault.Error {
		r.policyFailure(w, req, plan, state, fmt.Errorf("injected backend fault"))
		return
	}
	response := &http.Response{StatusCode: fault.Status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(fault.Body))}
	if response.StatusCode == 0 {
		response.StatusCode = http.StatusServiceUnavailable
	}
	state.Response = response
	if err := policy.Execute(plan.Outbound, state); err != nil {
		r.policyFailure(w, req, plan, state, err)
		return
	}
	if state.Returned {
		writePolicyResponse(w, state)
		return
	}
	writeForwardedResponse(w, response, state)
}

func isWebSocketRequest(req *http.Request) bool {
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, value := range strings.Split(req.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(value), "upgrade") {
			return true
		}
	}
	return false
}

func (r *Runtime) serveWebSocket(w http.ResponseWriter, req *http.Request, backend, path string) {
	base, err := websocketBackendURL(backend, path, req.URL.RawQuery)
	if err != nil {
		gatewayError(w, http.StatusBadGateway, "BackendConnectionFailure", "The WebSocket backend URL is invalid.")
		return
	}
	config, _ := websocket.NewConfig(base.String(), "http://"+base.Host)
	config.Header = websocketHeaders(req.Header)
	binary := strings.EqualFold(req.Header.Get("Sec-WebSocket-Protocol"), "binary")
	if binary {
		config.Protocol = []string{"binary"}
	}
	server := websocket.Server{Handler: websocket.Handler(func(client *websocket.Conn) {
		if binary {
			client.PayloadType = websocket.BinaryFrame
		} else {
			client.PayloadType = websocket.TextFrame
		}
		backendConfig := *config
		backendConn, dialErr := websocket.DialConfig(&backendConfig)
		if dialErr != nil {
			_ = client.Close()
			return
		}
		backendConn.PayloadType = client.PayloadType
		defer backendConn.Close()
		done := make(chan struct{}, 1)
		go func() {
			proxyWebSocketMessages(backendConn, client)
			_ = backendConn.Close()
			done <- struct{}{}
		}()
		proxyWebSocketMessages(client, backendConn)
		_ = client.Close()
		<-done
	})}
	server.ServeHTTP(w, req)
}

func websocketBackendURL(backend, path, query string) (*url.URL, error) {
	base, err := url.Parse(backend)
	if err != nil || base.Host == "" {
		return nil, fmt.Errorf("invalid WebSocket backend URL")
	}
	switch base.Scheme {
	case "http":
		base.Scheme = "ws"
	case "https":
		base.Scheme = "wss"
	case "ws", "wss":
	default:
		return nil, fmt.Errorf("unsupported WebSocket backend scheme %q", base.Scheme)
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/" + strings.TrimLeft(path, "/")
	base.RawQuery = query
	return base, nil
}

func websocketHeaders(source http.Header) http.Header {
	result := make(http.Header)
	for name, values := range source {
		lower := strings.ToLower(name)
		if lower == "connection" || lower == "upgrade" || strings.HasPrefix(lower, "sec-websocket-") {
			continue
		}
		result[name] = append([]string(nil), values...)
	}
	return result
}

func proxyWebSocketMessages(destination, source *websocket.Conn) {
	for {
		if source.PayloadType == websocket.TextFrame {
			var message string
			if err := websocket.Message.Receive(source, &message); err != nil {
				return
			}
			_ = websocket.Message.Send(destination, message)
			continue
		}
		var message []byte
		if err := websocket.Message.Receive(source, &message); err != nil {
			return
		}
		_ = websocket.Message.Send(destination, message)
	}
}

func writeGatewayBody(w http.ResponseWriter, response *http.Response) {
	if strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream") {
		if flusher, ok := w.(http.Flusher); ok {
			buffer := make([]byte, 4096)
			for {
				read, err := response.Body.Read(buffer)
				if read > 0 {
					_, _ = w.Write(buffer[:read])
					flusher.Flush()
				}
				if err != nil {
					return
				}
			}
		}
	}
	_, _ = io.Copy(w, response.Body)
}

func (r *Runtime) circuitOpen(service *Service, backendID string, now time.Time) bool {
	rule, ok := backendCircuitRule(service, backendID)
	if !ok {
		return false
	}
	key := strings.ToLower(service.Name + "/" + backendID)
	r.breakerMu.Lock()
	defer r.breakerMu.Unlock()
	state := r.breakers[key]
	if state.openedUntil.After(now) {
		return true
	}
	if !state.openedUntil.IsZero() && !state.openedUntil.After(now) {
		state.openedUntil = time.Time{}
		state.failures = nil
		r.breakers[key] = state
	}
	_ = rule
	return false
}

func (r *Runtime) recordCircuit(service *Service, backendID string, response *http.Response, requestErr error, now time.Time) {
	rule, ok := backendCircuitRule(service, backendID)
	if !ok {
		return
	}
	failure := requestErr != nil
	if response != nil {
		failure = response.StatusCode >= rule.statusMin && response.StatusCode <= rule.statusMax
	}
	key := strings.ToLower(service.Name + "/" + backendID)
	r.breakerMu.Lock()
	defer r.breakerMu.Unlock()
	state := r.breakers[key]
	if !failure {
		state.failures = nil
		state.openedUntil = time.Time{}
		r.breakers[key] = state
		return
	}
	cutoff := now.Add(-rule.interval)
	kept := state.failures[:0]
	for _, failureAt := range state.failures {
		if failureAt.After(cutoff) {
			kept = append(kept, failureAt)
		}
	}
	state.failures = append(kept, now)
	if len(state.failures) >= rule.count {
		state.openedUntil = now.Add(rule.tripDuration)
	}
	r.breakers[key] = state
}

func backendCircuitRule(service *Service, backendID string) (circuitRule, bool) {
	if service == nil || backendID == "" {
		return circuitRule{}, false
	}
	backend, ok := service.Backends[strings.ToLower(backendID)]
	if !ok {
		return circuitRule{}, false
	}
	properties, _ := backend.Document["properties"].(map[string]any)
	circuit, _ := properties["circuitBreaker"].(map[string]any)
	rules, _ := circuit["rules"].([]any)
	if len(rules) == 0 {
		return circuitRule{}, false
	}
	ruleDocument, _ := rules[0].(map[string]any)
	failureCondition, _ := ruleDocument["failureCondition"].(map[string]any)
	rule := circuitRule{count: intNumber(failureCondition["count"]), interval: parseAPIMDuration(failureCondition["interval"], time.Minute), tripDuration: parseAPIMDuration(ruleDocument["tripDuration"], time.Minute), statusMin: 500, statusMax: 599}
	if rule.count <= 0 {
		return circuitRule{}, false
	}
	if ranges, ok := failureCondition["statusCodeRanges"].([]any); ok && len(ranges) > 0 {
		if first, ok := ranges[0].(map[string]any); ok {
			rule.statusMin = intNumber(first["min"])
			rule.statusMax = intNumber(first["max"])
		}
	}
	return rule, rule.statusMin <= rule.statusMax && rule.tripDuration >= 0
}

func intNumber(value any) int {
	switch number := value.(type) {
	case int:
		return number
	case int64:
		return int(number)
	case float64:
		return int(number)
	default:
		return 0
	}
}

func parseAPIMDuration(value any, fallback time.Duration) time.Duration {
	text, ok := value.(string)
	if !ok || text == "" {
		return fallback
	}
	if parsed, err := time.ParseDuration(text); err == nil {
		return parsed
	}
	var seconds float64
	if _, err := fmt.Sscanf(strings.ToUpper(text), "PT%fS", &seconds); err == nil {
		return time.Duration(seconds * float64(time.Second))
	}
	return fallback
}

type diagnosticWriter struct {
	http.ResponseWriter
	status      int
	body        []byte
	bodyLimit   int
	requestBody string
}

func (w *diagnosticWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer does not support hijacking")
	}
	return hijacker.Hijack()
}

func (w *diagnosticWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *diagnosticWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *diagnosticWriter) Write(value []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.bodyLimit > 0 && len(w.body) < w.bodyLimit {
		need := w.bodyLimit - len(w.body)
		if len(value) > need {
			w.body = append(w.body, value[:need]...)
		} else {
			w.body = append(w.body, value...)
		}
	}
	return w.ResponseWriter.Write(value)
}

func (r *Runtime) emitDiagnostics(req *http.Request, service *Service, route *Route, output *diagnosticWriter, started time.Time) {
	eventStore := r.eventStore.Load()
	if eventStore == nil {
		return
	}
	status := output.status
	if status == 0 {
		status = http.StatusOK
	}
	correlationID := req.Header.Get("traceparent")
	if correlationID == "" {
		correlationID = req.Header.Get("Request-Id")
	}
	if correlationID == "" {
		correlationID = store.NewOpaqueID()
	}
	values := append(append([]model.Diagnostic{}, service.Diagnostics...), route.Diagnostics...)
	seen := map[string]bool{}
	for _, diagnostic := range values {
		key := strings.ToLower(diagnostic.ID())
		if seen[key] {
			continue
		}
		seen[key] = true
		if (status < http.StatusBadRequest || diagnostic.AlwaysLog != "allErrors") && !diagnosticSampled(correlationID, diagnostic.SamplingPercentage) {
			continue
		}
		clientIP := ""
		if diagnostic.LogClientIP {
			clientIP, _, _ = net.SplitHostPort(req.RemoteAddr)
			if clientIP == "" {
				clientIP = req.RemoteAddr
			}
		}
		metadata := diagnosticMetadata(diagnostic, req, output)
		_ = eventStore.AddDiagnosticEvent(model.DiagnosticEvent{
			ID: store.NewOpaqueID(), ServiceID: route.API.ServiceID, APIID: route.API.ID(),
			DiagnosticID: diagnostic.ID(), CorrelationID: correlationID, Method: req.Method,
			Path: req.URL.Path, StatusCode: status, Timestamp: eventStore.Clock.Now(),
			DurationNanos: time.Since(started).Nanoseconds(), ClientIP: clientIP, Metadata: metadata,
		})
	}
}

func diagnosticMetadata(diagnostic model.Diagnostic, req *http.Request, output *diagnosticWriter) map[string]any {
	properties, _ := diagnostic.Document["properties"].(map[string]any)
	logHeaders, _ := properties["logHeaders"].(bool)
	reqBytes := diagnosticBytes(properties, "frontend", "request")
	respBytes := diagnosticBytes(properties, "frontend", "response")
	if !logHeaders && reqBytes <= 0 && respBytes <= 0 {
		return nil
	}
	result := map[string]any{}
	if logHeaders {
		result["requestHeaders"] = maskedHeaders(req.Header)
		result["responseHeaders"] = maskedHeaders(output.Header())
	}
	if reqBytes > 0 {
		result["requestBody"] = maskedBody(truncateBody(output.requestBody, reqBytes), req.Header)
	}
	if respBytes > 0 {
		result["responseBody"] = maskedBody(truncateBody(string(output.body), respBytes), output.Header())
	}
	return result
}

func diagnosticBodyLimits(values []model.Diagnostic) (requestLimit, responseLimit int) {
	for _, diagnostic := range values {
		properties, _ := diagnostic.Document["properties"].(map[string]any)
		if n := diagnosticBytes(properties, "frontend", "request"); n > requestLimit {
			requestLimit = n
		}
		if n := diagnosticBytes(properties, "frontend", "response"); n > responseLimit {
			responseLimit = n
		}
	}
	return requestLimit, responseLimit
}

const maxDiagnosticBodyBytes = 8192

func diagnosticBytes(properties map[string]any, section, direction string) int {
	frontend, _ := properties[section].(map[string]any)
	side, _ := frontend[direction].(map[string]any)
	body, _ := side["body"].(map[string]any)
	var n int
	switch value := body["bytes"].(type) {
	case float64:
		n = int(value)
	case int:
		n = value
	default:
		return 0
	}
	if n <= 0 {
		return 0
	}
	if n > maxDiagnosticBodyBytes {
		return maxDiagnosticBodyBytes
	}
	return n
}

func snapshotRequestBody(req *http.Request, limit int) string {
	if req == nil || limit <= 0 || (req.Body == nil && req.GetBody == nil) {
		return ""
	}
	var body io.ReadCloser
	var err error
	if req.GetBody != nil {
		body, err = req.GetBody()
		if err != nil {
			return ""
		}
	} else {
		body = req.Body
	}
	value, err := io.ReadAll(body)
	_ = body.Close()
	if err != nil {
		return ""
	}
	if req.GetBody == nil {
		req.Body = io.NopCloser(bytes.NewReader(value))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(value)), nil
		}
		req.ContentLength = int64(len(value))
	}
	return truncateBody(string(value), limit)
}

func truncateBody(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit]
}

func maskedHeaders(headers http.Header) map[string][]string {
	result := make(map[string][]string, len(headers))
	for name, values := range headers {
		if secretHeader(name) {
			result[name] = []string{"[REDACTED]"}
			continue
		}
		result[name] = append([]string(nil), values...)
	}
	return result
}

func maskedBody(value string, headers http.Header) string {
	for name, values := range headers {
		if !secretHeader(name) {
			continue
		}
		for _, secret := range values {
			if secret != "" {
				value = strings.ReplaceAll(value, secret, "[REDACTED]")
			}
		}
	}
	return value
}

func secretHeader(name string) bool {
	switch strings.ToLower(name) {
	case "authorization", "cookie", "set-cookie", "ocp-apim-subscription-key", "x-api-key":
		return true
	default:
		return false
	}
}

func diagnosticSampled(correlationID string, percentage float64) bool {
	if percentage <= 0 {
		return false
	}
	if percentage >= 100 {
		return true
	}
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(correlationID))
	return float64(hash.Sum32()%10000) < percentage*100
}

const traceLimit = 100

type traceWriter struct {
	http.ResponseWriter
	status int
}

func (w *traceWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *traceWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (r *Runtime) beginTrace(w http.ResponseWriter, req *http.Request) (*Trace, *traceWriter) {
	if !strings.EqualFold(req.Header.Get("Ocp-Apim-Trace"), "true") {
		return nil, nil
	}
	id := store.NewOpaqueID()
	w.Header().Set("Ocp-Apim-Trace-Location", "/_emulator/traces/"+id)
	return &Trace{ID: id, Method: req.Method, Path: req.URL.RequestURI(), Events: []TraceEvent{}}, &traceWriter{ResponseWriter: w}
}

func (r *Runtime) finishTrace(trace *Trace, writer *traceWriter) {
	trace.Status = writer.status
	if trace.Status == 0 {
		trace.Status = http.StatusOK
	}
	r.traceMu.Lock()
	defer r.traceMu.Unlock()
	if len(r.traceOrder) == traceLimit {
		delete(r.traces, r.traceOrder[0])
		r.traceOrder = r.traceOrder[1:]
	}
	r.traces[trace.ID] = *trace
	r.traceOrder = append(r.traceOrder, trace.ID)
}

func traceEvent(trace *Trace, phase, detail string) {
	if trace != nil {
		trace.Events = append(trace.Events, TraceEvent{Phase: phase, Detail: detail})
	}
}

// GetTrace returns a previously completed gateway trace.
func (r *Runtime) GetTrace(id string) (Trace, bool) {
	r.traceMu.RLock()
	defer r.traceMu.RUnlock()
	value, ok := r.traces[id]
	return value, ok
}

func (r *Runtime) policyFailure(w http.ResponseWriter, req *http.Request, plan policy.Plan, state *policy.State, cause error) {
	state.LastError = cause
	state.Response = &http.Response{Header: make(http.Header)}
	if err := policy.Execute(plan.OnError, state); err == nil && state.Returned {
		writePolicyResponse(w, state)
		return
	}
	gatewayError(w, http.StatusInternalServerError, "PolicyExecutionFailure", cause.Error())
}

func (r *Runtime) forward(original *http.Request, backend, path string) (*http.Response, error) {
	return forwardWithClient(r.client, original, backend, path)
}

func forwardWithRetry(client *http.Client, original *http.Request, backend, path string, actions []policy.Action) (*http.Response, error) {
	var retry *policy.Action
	for index := range actions {
		if actions[index].Kind == policy.ActionRetry {
			retry = &actions[index]
			break
		}
	}
	if retry == nil {
		return forwardWithClient(client, original, backend, path)
	}
	var body []byte
	var err error
	if original.Body != nil {
		body, err = io.ReadAll(original.Body)
		if err != nil {
			return nil, err
		}
		_ = original.Body.Close()
	}
	for attempt := 0; ; attempt++ {
		if body != nil {
			original.Body = io.NopCloser(bytes.NewReader(body))
		}
		response, requestErr := forwardWithClient(client, original, backend, path)
		if attempt >= retry.RetryCount || !retryConditionMatches(retry.Condition, original, response, requestErr) {
			return response, requestErr
		}
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if retry.RetryInterval > 0 {
			timer := time.NewTimer(retry.RetryInterval)
			select {
			case <-timer.C:
			case <-original.Context().Done():
				timer.Stop()
				return nil, original.Context().Err()
			}
		}
	}
}

func retryConditionMatches(condition string, request *http.Request, response *http.Response, requestErr error) bool {
	if strings.TrimSpace(condition) == "" {
		if requestErr != nil {
			return true
		}
		return response != nil && response.StatusCode >= http.StatusInternalServerError
	}
	value, err := expression.EvalEnv(condition, expression.Bind(expression.Context{
		Request:   request,
		Response:  response,
		LastError: requestErr,
	}))
	if err != nil {
		return false
	}
	truth, ok := value.AsBool()
	return ok && truth
}

func forwardWithClient(client *http.Client, original *http.Request, backend, path string) (*http.Response, error) {
	base, err := url.Parse(backend)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("invalid backend URL %q", backend)
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/" + strings.TrimLeft(path, "/")
	base.RawQuery = original.URL.RawQuery
	request := original.Clone(original.Context())
	request.URL = base
	request.RequestURI = ""
	request.Host = base.Host
	return client.Do(request)
}

func backendHTTPClient(base *http.Client, service *Service, backendID string) (*http.Client, error) {
	if backendID == "" {
		return base, nil
	}
	backend, ok := service.Backends[strings.ToLower(backendID)]
	if !ok {
		return nil, fmt.Errorf("backend %q was not found", backendID)
	}
	ids := backendCertificateIDs(backend)
	validateChain, hasValidateChain := backendTLSSetting(backend, "validateCertificateChain")
	if len(ids) == 0 && (!hasValidateChain || validateChain) {
		return base, nil
	}
	transport, ok := base.Transport.(*http.Transport)
	if !ok {
		if base.Transport != nil {
			return nil, fmt.Errorf("backend client certificates require an HTTP transport")
		}
		transport = http.DefaultTransport.(*http.Transport)
	}
	tlsConfig := transport.TLSClientConfig
	transport = transport.Clone()
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	if hasValidateChain && !validateChain {
		tlsConfig.InsecureSkipVerify = true // APIM backend TLS explicitly permits untrusted chains.
	}
	for _, id := range ids {
		certificate, ok := service.Certificates[strings.ToLower(id)]
		if !ok {
			return nil, fmt.Errorf("backend %q references missing certificate %q", backendID, id)
		}
		value, err := certutil.TLSCertificate(certificate.Data, certificate.Password)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, value)
	}
	transport.TLSClientConfig = tlsConfig
	result := *base
	result.Transport = transport
	return &result, nil
}

func backendTLSSetting(backend model.Backend, name string) (bool, bool) {
	properties, _ := backend.Document["properties"].(map[string]any)
	tls, _ := properties["tls"].(map[string]any)
	value, present := tls[name]
	boolean, ok := value.(bool)
	return boolean, present && ok
}

func backendCertificateIDs(backend model.Backend) []string {
	var document struct {
		Properties struct {
			Credentials struct {
				CertificateIDs []string `json:"certificateIds"`
			} `json:"credentials"`
		} `json:"properties"`
	}
	encoded, _ := json.Marshal(backend.Document)
	_ = json.Unmarshal(encoded, &document)
	return document.Properties.Credentials.CertificateIDs
}

func validateBackendCertificates(backends map[string]model.Backend, certificates map[string]model.Certificate) error {
	for name, backend := range backends {
		for _, id := range backendCertificateIDs(backend) {
			if _, ok := certificates[strings.ToLower(id)]; !ok {
				return fmt.Errorf("backend %q references missing certificate %q", name, id)
			}
		}
	}
	return nil
}

func serviceFromHost(host, fallback string) string {
	name := host
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		name = parsed
	}
	for _, suffix := range []string{".azure-api.localhost", ".azure-api.net"} {
		if strings.HasSuffix(strings.ToLower(name), suffix) {
			return name[:len(name)-len(suffix)]
		}
	}
	return fallback
}

func serviceForHost(snapshot *Snapshot, host, fallback string) string {
	normalized := strings.ToLower(host)
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		normalized = strings.ToLower(parsed)
	}
	names := make([]string, 0, len(snapshot.Services))
	for name := range snapshot.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		service := snapshot.Services[name]
		if service.Hostnames[normalized] {
			return service.Name
		}
	}
	return serviceFromHost(host, fallback)
}

func customHostnames(document map[string]any) map[string]bool {
	result := map[string]bool{}
	collect := func(value any) {
		entries, ok := value.([]any)
		if !ok {
			return
		}
		for _, entry := range entries {
			configuration, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			if host, ok := configuration["hostName"].(string); ok && strings.TrimSpace(host) != "" {
				result[strings.ToLower(strings.TrimSpace(host))] = true
			}
		}
	}
	collect(document["hostnameConfigurations"])
	if properties, ok := document["properties"].(map[string]any); ok {
		collect(properties["hostnameConfigurations"])
	}
	return result
}

func publicNetworkAccess(document map[string]any) bool {
	properties, _ := document["properties"].(map[string]any)
	value, _ := properties["publicNetworkAccess"].(string)
	return !strings.EqualFold(strings.TrimSpace(value), "disabled")
}

func matchRoute(routes []*Route, request *http.Request) (*Route, string) {
	clean := strings.TrimPrefix(request.URL.Path, "/")
	for _, route := range routes {
		prefix := strings.Trim(route.API.Path, "/")
		if route.VersionSet != nil {
			switch route.VersionSet.VersioningScheme {
			case "Segment":
				prefix = strings.Trim(prefix+"/"+route.API.Version, "/")
			case "Header":
				if request.Header.Get(route.VersionSet.VersionHeaderName) != route.API.Version {
					continue
				}
			case "Query":
				if request.URL.Query().Get(route.VersionSet.VersionQueryName) != route.API.Version {
					continue
				}
			}
		}
		if prefix == "" {
			return route, "/" + clean
		}
		if clean == prefix {
			return route, "/"
		}
		if strings.HasPrefix(clean, prefix+"/") {
			return route, "/" + strings.TrimPrefix(clean, prefix+"/")
		}
	}
	return nil, ""
}

func matchOperation(operations []model.Operation, method, path string) bool {
	_, matched := matchOperationValue(operations, method, path)
	return matched
}

func matchOperationValue(operations []model.Operation, method, path string) (model.Operation, bool) {
	for _, operation := range operations {
		if strings.EqualFold(operation.Method, method) && templateMatches(operation.URLTemplate, path) {
			return operation, true
		}
	}
	return model.Operation{}, false
}

func templateMatches(template, path string) bool {
	want, got := splitPath(template), splitPath(path)
	if len(want) != len(got) {
		return false
	}
	for index := range want {
		if strings.HasPrefix(want[index], "{") && strings.HasSuffix(want[index], "}") {
			continue
		}
		if want[index] != got[index] {
			return false
		}
	}
	return true
}

func splitPath(path string) []string {
	value := strings.Trim(path, "/")
	if value == "" {
		return nil
	}
	return strings.Split(value, "/")
}
func subscriptionKey(req *http.Request) string {
	if key := req.Header.Get("Ocp-Apim-Subscription-Key"); key != "" {
		return key
	}
	return req.URL.Query().Get("subscription-key")
}
func validSubscription(req *http.Request, keys map[string]bool) bool {
	return keys[subscriptionKey(req)]
}

func copyHeaders(target, source http.Header) {
	for name, values := range source {
		if hopByHop(strings.ToLower(name)) {
			continue
		}
		target.Del(name)
		for _, value := range values {
			target.Add(name, value)
		}
	}
}

func hopByHop(name string) bool {
	switch name {
	case "connection", "proxy-connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func writeForwardedResponse(w http.ResponseWriter, response *http.Response, state *policy.State) {
	copyHeaders(w.Header(), response.Header)
	copyHeaders(w.Header(), state.Headers)
	status := response.StatusCode
	if state.StatusCode != 0 {
		status = state.StatusCode
	}
	w.WriteHeader(status)
	if state.BodySet {
		writeResponseBody(w, state.Body)
	} else {
		writeGatewayBody(w, response)
	}
}

func writePolicyResponse(w http.ResponseWriter, state *policy.State) {
	copyHeaders(w.Header(), state.Headers)
	status := state.StatusCode
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	writeResponseBody(w, state.Body)
}

// writeResponseBody writes a policy or backend payload. These bodies are API
// content (JSON, XML, text), not HTML documents; escaping them would change
// APIM set-body / return-response semantics.
func writeResponseBody(w http.ResponseWriter, body string) {
	// codeql[go/reflected-xss] API payloads are not HTML documents.
	_, _ = io.WriteString(w, body)
}

func gatewayError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"statusCode": status, "error": map[string]string{"code": code, "message": message}})
}

// isResolverScope reports whether a policy scope addresses a GraphQL resolver.
func isResolverScope(scopeID string) bool {
	return strings.Contains(strings.ToLower(scopeID), "/resolvers/")
}
