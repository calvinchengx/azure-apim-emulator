// Package gateway compiles APIM resources into immutable request snapshots.
package gateway

import (
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	certutil "github.com/calvinchengx/azure-apim-emulator/internal/certificate"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
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
	Name         string
	Hostnames    map[string]bool
	Routes       []*Route
	Backends     map[string]model.Backend
	Certificates map[string]model.Certificate
	Diagnostics  []model.Diagnostic
}

// Route is a compiled API route.
type Route struct {
	API          model.API
	VersionSet   *model.APIVersionSet
	Operations   []model.Operation
	Plan         policy.Plan
	AcceptedKeys map[string]bool
	Diagnostics  []model.Diagnostic
}

// Runtime atomically publishes snapshots and serves gateway traffic.
type Runtime struct {
	defaultService string
	client         *http.Client
	current        atomic.Pointer[Snapshot]
	traceMu        sync.RWMutex
	traces         map[string]Trace
	traceOrder     []string
	eventStore     atomic.Pointer[store.Store]
	breakerMu      sync.Mutex
	breakers       map[string]circuitState
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
	r := &Runtime{defaultService: defaultService, client: client, traces: map[string]Trace{}, breakers: map[string]circuitState{}}
	r.current.Store(&Snapshot{Services: map[string]*Service{}})
	return r
}

// Activate compiles all stored resources and atomically publishes them.
func (r *Runtime) Activate(st *store.Store, strict bool) error {
	services, apis, operations, _, links, subscriptions, policies, err := st.RuntimeData()
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
		snapshot.Services[strings.ToLower(item.Name)] = &Service{Name: item.Name, Hostnames: customHostnames(item.Document), Backends: backends[strings.ToLower(item.ID())], Certificates: certificates[strings.ToLower(item.ID())], Diagnostics: diagnostics[strings.ToLower(item.ID())]}
	}
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
		service.Routes = append(service.Routes, &Route{API: api, VersionSet: versionSet, Operations: operationsByAPI[strings.ToLower(api.ID())], Plan: policyByScope[strings.ToLower(api.ID())], AcceptedKeys: keysByAPI[strings.ToLower(api.ID())], Diagnostics: diagnostics[strings.ToLower(api.ID())]})
	}
	for _, service := range snapshot.Services {
		sort.SliceStable(service.Routes, func(i, j int) bool { return len(service.Routes[i].API.Path) > len(service.Routes[j].API.Path) })
	}
	r.current.Store(snapshot)
	r.eventStore.Store(st)
	return nil
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
	route, relative := matchRoute(service.Routes, req)
	if route == nil {
		gatewayError(w, http.StatusNotFound, "OperationNotFound", "Unable to match incoming request to an operation.")
		return
	}
	diagnosticStart := time.Now()
	diagnosticOutput := &diagnosticWriter{ResponseWriter: w}
	w = diagnosticOutput
	defer r.emitDiagnostics(req, service, route, diagnosticOutput, diagnosticStart)
	if trace != nil {
		trace.API = route.API.ID()
	}
	traceEvent(trace, "route", route.API.Path)
	if !matchOperation(route.Operations, req.Method, relative) {
		gatewayError(w, http.StatusNotFound, "OperationNotFound", "Unable to match incoming request to an operation.")
		return
	}
	if route.API.SubscriptionRequired && !validSubscription(req, route.AcceptedKeys) {
		message := "Access denied due to missing subscription key. Make sure to include subscription key when making requests to an API."
		if subscriptionKey(req) != "" {
			message = "Access denied due to invalid subscription key. Check that the key is active and belongs to the requested API."
		}
		gatewayError(w, http.StatusUnauthorized, "SubscriptionKeyInvalid", message)
		return
	}
	state := &policy.State{Request: req, BackendURL: route.API.ServiceURL, Path: relative, Headers: make(http.Header)}
	traceEvent(trace, "inbound", "")
	if err := policy.Execute(route.Plan.Inbound, state); err != nil {
		r.policyFailure(w, req, route.Plan, state, err)
		return
	}
	if state.Returned {
		writePolicyResponse(w, state)
		return
	}
	traceEvent(trace, "backend", state.BackendURL)
	if err := policy.Execute(route.Plan.Backend, state); err != nil {
		r.policyFailure(w, req, route.Plan, state, err)
		return
	}
	if state.Returned {
		writePolicyResponse(w, state)
		return
	}
	client, err := backendHTTPClient(r.client, service, state.BackendID)
	if err != nil {
		r.policyFailure(w, req, route.Plan, state, err)
		return
	}
	if r.circuitOpen(service, state.BackendID, time.Now()) {
		r.policyFailure(w, req, route.Plan, state, fmt.Errorf("backend circuit breaker is open"))
		return
	}
	response, err := forwardWithRetry(client, req, state.BackendURL, state.Path, route.Plan.Backend)
	r.recordCircuit(service, state.BackendID, response, err, time.Now())
	if err != nil {
		r.policyFailure(w, req, route.Plan, state, fmt.Errorf("backend request failed: %w", err))
		return
	}
	defer response.Body.Close()
	state.Response = response
	traceEvent(trace, "outbound", "")
	if err := policy.Execute(route.Plan.Outbound, state); err != nil {
		r.policyFailure(w, req, route.Plan, state, err)
		return
	}
	if state.Returned {
		writePolicyResponse(w, state)
		return
	}
	copyHeaders(w.Header(), response.Header)
	copyHeaders(w.Header(), state.Headers)
	w.WriteHeader(response.StatusCode)
	if state.BodySet {
		_, _ = io.WriteString(w, state.Body)
	} else {
		writeGatewayBody(w, response)
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
	status int
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
		_ = eventStore.AddDiagnosticEvent(model.DiagnosticEvent{
			ID: store.NewOpaqueID(), ServiceID: route.API.ServiceID, APIID: route.API.ID(),
			DiagnosticID: diagnostic.ID(), CorrelationID: correlationID, Method: req.Method,
			Path: req.URL.Path, StatusCode: status, Timestamp: eventStore.Clock.Now(),
			DurationNanos: time.Since(started).Nanoseconds(), ClientIP: clientIP,
		})
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
		if attempt >= retry.RetryCount || !retryConditionMatches(retry.Condition, response, requestErr) {
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

var retryStatusCondition = regexp.MustCompile(`(?i)context\.Response\.StatusCode\s*(==|!=|>=|<=|>|<)\s*(\d+)`)

func retryConditionMatches(condition string, response *http.Response, requestErr error) bool {
	if requestErr != nil {
		value := strings.ToLower(condition)
		return strings.TrimSpace(condition) == "" || strings.Contains(value, "lastresult") || strings.Contains(value, "lasterror")
	}
	if response == nil {
		return false
	}
	condition = strings.TrimSpace(condition)
	if condition == "" {
		return response.StatusCode >= http.StatusInternalServerError
	}
	matches := retryStatusCondition.FindStringSubmatch(condition)
	if len(matches) != 3 {
		return false
	}
	status, _ := strconv.Atoi(matches[2])
	switch matches[1] {
	case "==":
		return response.StatusCode == status
	case "!=":
		return response.StatusCode != status
	case ">=":
		return response.StatusCode >= status
	case "<=":
		return response.StatusCode <= status
	case ">":
		return response.StatusCode > status
	default:
		return response.StatusCode < status
	}
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
	for _, operation := range operations {
		if strings.EqualFold(operation.Method, method) && templateMatches(operation.URLTemplate, path) {
			return true
		}
	}
	return false
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

func writePolicyResponse(w http.ResponseWriter, state *policy.State) {
	copyHeaders(w.Header(), state.Headers)
	status := state.StatusCode
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, state.Body)
}

func gatewayError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"statusCode": status, "error": map[string]string{"code": code, "message": message}})
}
