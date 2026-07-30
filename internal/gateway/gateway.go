// Package gateway compiles APIM resources into immutable request snapshots.
package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

// Snapshot is the complete active gateway configuration.
type Snapshot struct {
	Services map[string]*Service
}

// Service is compiled runtime state for one APIM service.
type Service struct {
	Name   string
	Routes []*Route
}

// Route is a compiled API route.
type Route struct {
	API          model.API
	Operations   []model.Operation
	Plan         policy.Plan
	AcceptedKeys map[string]bool
}

// Runtime atomically publishes snapshots and serves gateway traffic.
type Runtime struct {
	defaultService string
	client         *http.Client
	current        atomic.Pointer[Snapshot]
	traceMu        sync.RWMutex
	traces         map[string]Trace
	traceOrder     []string
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
	r := &Runtime{defaultService: defaultService, client: client, traces: map[string]Trace{}}
	r.current.Store(&Snapshot{Services: map[string]*Service{}})
	return r
}

// Activate compiles all stored resources and atomically publishes them.
func (r *Runtime) Activate(st *store.Store, strict bool) error {
	services, apis, operations, _, links, subscriptions, policies, err := st.RuntimeData()
	if err != nil {
		return err
	}
	policyByScope := map[string]policy.Plan{}
	for _, item := range policies {
		plan, err := policy.Compile(item.Value, strict)
		if err != nil {
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
			allowed := strings.EqualFold(subscription.Scope, api.ID()) || strings.EqualFold(subscription.Scope, api.ServiceID)
			if linkedAPIs := links[subscription.Scope]; !allowed {
				for _, linkedAPI := range linkedAPIs {
					if strings.EqualFold(linkedAPI, api.ID()) {
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
		snapshot.Services[strings.ToLower(item.Name)] = &Service{Name: item.Name}
	}
	for _, api := range apis {
		serviceName := serviceNameFromID(api.ServiceID)
		service := snapshot.Services[strings.ToLower(serviceName)]
		if service == nil {
			return fmt.Errorf("API %s references missing service", api.ID())
		}
		service.Routes = append(service.Routes, &Route{API: api, Operations: operationsByAPI[strings.ToLower(api.ID())], Plan: policyByScope[strings.ToLower(api.ID())], AcceptedKeys: keysByAPI[strings.ToLower(api.ID())]})
	}
	for _, service := range snapshot.Services {
		sort.SliceStable(service.Routes, func(i, j int) bool { return len(service.Routes[i].API.Path) > len(service.Routes[j].API.Path) })
	}
	r.current.Store(snapshot)
	return nil
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

// ServeHTTP handles managed gateway requests.
func (r *Runtime) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	trace, tracedWriter := r.beginTrace(w, req)
	if trace != nil {
		w = tracedWriter
		defer r.finishTrace(trace, tracedWriter)
	}
	snapshot := r.current.Load()
	serviceName := serviceFromHost(req.Host, r.defaultService)
	traceEvent(trace, "ingress", serviceName)
	service := snapshot.Services[strings.ToLower(serviceName)]
	if service == nil {
		gatewayError(w, http.StatusNotFound, "ServiceNotFound", "API Management service was not found.")
		return
	}
	route, relative := matchRoute(service.Routes, req.URL.Path)
	if route == nil {
		gatewayError(w, http.StatusNotFound, "OperationNotFound", "Unable to match incoming request to an operation.")
		return
	}
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
	response, err := r.forward(req, state.BackendURL, state.Path)
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
	_, _ = io.Copy(w, response.Body)
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
	return r.client.Do(request)
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

func matchRoute(routes []*Route, path string) (*Route, string) {
	clean := strings.TrimPrefix(path, "/")
	for _, route := range routes {
		prefix := strings.Trim(route.API.Path, "/")
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
