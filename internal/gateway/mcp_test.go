package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	mcpc "github.com/calvinchengx/azure-apim-emulator/internal/mcp"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

func mcpRuntime(t *testing.T, apiDocument map[string]any) (*Runtime, *[]string) {
	t.Helper()
	seen := &[]string{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		*seen = append(*seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
		if strings.Contains(r.URL.Path, "missing") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"no such order"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"url":%q}`, r.URL.RequestURI())
	}))
	t.Cleanup(backend.Close)

	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	api, err := st.UpsertAPI(model.API{
		ServiceID: service.ID(), Name: "orders", DisplayName: "Orders", Path: "orders",
		ServiceURL: backend.URL, IsCurrent: true, Document: apiDocument,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertOperation(model.Operation{
		APIID: api.ID(), Name: "get-order", DisplayName: "Get order", Method: http.MethodGet, URLTemplate: "/orders/{orderId}",
		Document: map[string]any{"properties": map[string]any{
			"description":        "Fetch one order.",
			"templateParameters": []any{map[string]any{"name": "orderId", "type": "string"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertOperation(model.Operation{
		APIID: api.ID(), Name: "create-order", DisplayName: "Create order", Method: http.MethodPost, URLTemplate: "/orders",
	}); err != nil {
		t.Fatal(err)
	}
	runtime := New("emulator", nil)
	if err := runtime.Activate(st, true); err != nil {
		t.Fatal(err)
	}
	return runtime, seen
}

func mcpCall(t *testing.T, runtime *Runtime, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/orders/mcp", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, request)
	var decoded map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &decoded)
	return recorder, decoded
}

// THE DEFECT THIS FOUND, and it predates MCP. Azure's REST contract carries the
// API type as `properties.type`, which is what Microsoft's SDK sends; this
// emulator read only `properties.apiType`. Every existing protocol witness set
// the type with a raw ARM PUT, so none of them could see it: an API created
// through the official SDK was stored, echoed back on GET looking correct, and
// then served as though it had no type at all.
func TestAPITypeIsReadUnderBothSpellings(t *testing.T) {
	for _, spelling := range []string{"type", "apiType"} {
		t.Run(spelling, func(t *testing.T) {
			runtime, _ := mcpRuntime(t, map[string]any{"properties": map[string]any{spelling: "mcp"}})
			recorder, decoded := mcpCall(t, runtime, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
			if recorder.Code != http.StatusOK {
				t.Fatalf("%s spelling was not recognised: %d %s", spelling, recorder.Code, recorder.Body.String())
			}
			result, _ := decoded["result"].(map[string]any)
			if tools, _ := result["tools"].([]any); len(tools) != 2 {
				t.Fatalf("tools = %v", result)
			}
		})
	}
	// `type` wins when both are present and disagree, because it is the name
	// Azure's own contract uses.
	runtime, _ := mcpRuntime(t, map[string]any{"properties": map[string]any{"type": "mcp", "apiType": "http"}})
	if recorder, _ := mcpCall(t, runtime, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); recorder.Code != http.StatusOK {
		t.Fatalf("the wire spelling did not win: %d", recorder.Code)
	}
}

func TestMCPHandshakeAndToolListing(t *testing.T) {
	runtime, _ := mcpRuntime(t, map[string]any{"properties": map[string]any{"type": "mcp"}})

	recorder, decoded := mcpCall(t, runtime, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("initialize = %d", recorder.Code)
	}
	// The session id is what the client echoes on every later request; without
	// it the reference client refuses to continue.
	if recorder.Header().Get("Mcp-Session-Id") == "" {
		t.Fatal("initialize returned no session id")
	}
	result, _ := decoded["result"].(map[string]any)
	if result["protocolVersion"] != "2025-06-18" {
		t.Fatalf("a supported version was not honoured: %v", result["protocolVersion"])
	}
	serverInfo, _ := result["serverInfo"].(map[string]any)
	if serverInfo["name"] != "Orders" {
		t.Fatalf("serverInfo = %v", serverInfo)
	}

	// A notification expects no reply at all; answering one makes the reference
	// client log a protocol error.
	notification := httptest.NewRequest(http.MethodPost, "/orders/mcp", strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	notified := httptest.NewRecorder()
	runtime.ServeHTTP(notified, notification)
	if notified.Code != http.StatusAccepted || notified.Body.Len() != 0 {
		t.Fatalf("notification = %d %q", notified.Code, notified.Body.String())
	}

	_, listed := mcpCall(t, runtime, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	tools, _ := listed["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("tools = %v", listed)
	}
	first, _ := tools[0].(map[string]any)
	if first["name"] != "create-order" {
		t.Fatalf("tools are not in a stable order: %v", first)
	}

	if _, ponged := mcpCall(t, runtime, `{"jsonrpc":"2.0","id":3,"method":"ping"}`); ponged["result"] == nil {
		t.Fatalf("ping = %v", ponged)
	}
}

func TestMCPToolCallReachesTheOperationsBackend(t *testing.T) {
	runtime, seen := mcpRuntime(t, map[string]any{"properties": map[string]any{"type": "mcp"}})

	_, called := mcpCall(t, runtime, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get-order","arguments":{"orderId":"A-1"}}}`)
	result, _ := called["result"].(map[string]any)
	if result["isError"] == true {
		t.Fatalf("tool call failed: %v", result)
	}
	if len(*seen) != 1 || (*seen)[0] != "GET /orders/A-1 " {
		t.Fatalf("the backend saw %v", *seen)
	}
	content, _ := result["content"].([]any)
	entry, _ := content[0].(map[string]any)
	if !strings.Contains(fmt.Sprint(entry["text"]), "/orders/A-1") {
		t.Fatalf("content = %v", content)
	}

	_, posted := mcpCall(t, runtime, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"create-order","arguments":{"body":"{\"sku\":\"widget\"}"}}}`)
	if posted["result"].(map[string]any)["isError"] == true {
		t.Fatalf("POST tool failed: %v", posted)
	}
	if len(*seen) != 2 || !strings.HasPrefix((*seen)[1], "POST /orders ") || !strings.Contains((*seen)[1], "widget") {
		t.Fatalf("the backend saw %v", *seen)
	}
}

// A backend that refuses is a FAILED TOOL, not a broken protocol: the
// conversation is healthy and the tool is not, which is what lets a model retry
// or apologise rather than drop the session.
func TestMCPBackendFailureIsAToolError(t *testing.T) {
	runtime, _ := mcpRuntime(t, map[string]any{"properties": map[string]any{"type": "mcp"}})
	_, called := mcpCall(t, runtime, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get-order","arguments":{"orderId":"missing"}}}`)
	if called["error"] != nil {
		t.Fatalf("a backend 404 became a protocol error: %v", called["error"])
	}
	result, _ := called["result"].(map[string]any)
	if result["isError"] != true {
		t.Fatalf("a backend 404 was reported as success: %v", result)
	}
}

func TestMCPProtocolRefusals(t *testing.T) {
	runtime, seen := mcpRuntime(t, map[string]any{"properties": map[string]any{"type": "mcp"}})

	for _, test := range []struct {
		name, body string
		code       float64
	}{
		{"unknown method", `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`, -32601},
		{"unknown tool", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"drop-database","arguments":{}}}`, -32602},
		{"missing required argument", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get-order","arguments":{}}}`, -32602},
		{"params not an object", `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":"nonsense"}`, -32602},
	} {
		_, decoded := mcpCall(t, runtime, test.body)
		failure, _ := decoded["error"].(map[string]any)
		if failure == nil || failure["code"] != test.code {
			t.Fatalf("%s = %v", test.name, decoded)
		}
	}
	// None of those reached the backend, which is what makes the refusals worth
	// having rather than merely tidy.
	if len(*seen) != 0 {
		t.Fatalf("a refused call reached the backend: %v", *seen)
	}

	unparsable := httptest.NewRequest(http.MethodPost, "/orders/mcp", strings.NewReader(`not json`))
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, unparsable)
	var decoded map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &decoded)
	if failure, _ := decoded["error"].(map[string]any); failure == nil || failure["code"] != float64(-32600) {
		t.Fatalf("unparsable body = %s", recorder.Body.String())
	}
}

// The client opens a GET for server-initiated messages and tolerates a refusal.
// Holding a stream open that will never carry anything would keep a connection
// per client for nothing.
func TestMCPDeclinesTheServerStream(t *testing.T) {
	runtime, _ := mcpRuntime(t, map[string]any{"properties": map[string]any{"type": "mcp"}})
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		request := httptest.NewRequest(method, "/orders/mcp", nil)
		recorder := httptest.NewRecorder()
		runtime.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s = %d", method, recorder.Code)
		}
		if recorder.Header().Get("Allow") != http.MethodPost {
			t.Fatalf("%s carried no Allow header", method)
		}
	}
}

// An API that is not an MCP server keeps proxying, and its /mcp path is just a
// path. Publishing one API as MCP must not change any other.
func TestNonMCPAPIIsUnaffected(t *testing.T) {
	runtime, seen := mcpRuntime(t, map[string]any{"properties": map[string]any{"type": "http"}})
	request := httptest.NewRequest(http.MethodGet, "/orders/orders/A-1", nil)
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("a plain API stopped proxying: %d %s", recorder.Code, recorder.Body.String())
	}
	if len(*seen) != 1 {
		t.Fatalf("the backend saw %v", *seen)
	}
}

// A tool call that cannot reach the backend at all is still a failed TOOL: the
// distinction between "your request was malformed" and "the thing I called is
// down" is what a model needs to decide whether retrying is sensible.
func TestMCPUnreachableBackendIsAToolError(t *testing.T) {
	st, _ := store.Open("", clock.New())
	defer func() { _ = st.Close() }()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	// Port 0 is never listening, so the dial fails rather than timing out.
	api, _ := st.UpsertAPI(model.API{
		ServiceID: service.ID(), Name: "orders", DisplayName: "Orders", Path: "orders",
		ServiceURL: "http://127.0.0.1:0", IsCurrent: true,
		Document: map[string]any{"properties": map[string]any{"type": "mcp"}},
	})
	_, _ = st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "get", DisplayName: "Get", Method: http.MethodGet, URLTemplate: "/thing"})
	runtime := New("emulator", nil)
	if err := runtime.Activate(st, true); err != nil {
		t.Fatal(err)
	}
	_, called := mcpCall(t, runtime, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get","arguments":{}}}`)
	if called["error"] != nil {
		t.Fatalf("an unreachable backend became a protocol error: %v", called["error"])
	}
	if called["result"].(map[string]any)["isError"] != true {
		t.Fatalf("an unreachable backend was reported as success: %v", called["result"])
	}
}

// An API with no display name is still a named MCP server: a client shows this
// to a user, and an empty name is worse than the identifier.
func TestMCPServerNameFallsBackToTheAPIIdentifier(t *testing.T) {
	st, _ := store.Open("", clock.New())
	defer func() { _ = st.Close() }()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	_, _ = st.UpsertAPI(model.API{
		ServiceID: service.ID(), Name: "orders", Path: "orders", ServiceURL: "https://backend.test", IsCurrent: true,
		Document: map[string]any{"properties": map[string]any{"type": "mcp"}},
	})
	runtime := New("emulator", nil)
	if err := runtime.Activate(st, true); err != nil {
		t.Fatal(err)
	}
	_, decoded := mcpCall(t, runtime, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`)
	info, _ := decoded["result"].(map[string]any)["serverInfo"].(map[string]any)
	if info["name"] != "orders" {
		t.Fatalf("serverInfo = %v", info)
	}
}

// A request body that fails mid-read is a malformed request, not a crash.
func TestMCPUnreadableRequestBody(t *testing.T) {
	runtime, _ := mcpRuntime(t, map[string]any{"properties": map[string]any{"type": "mcp"}})
	request := httptest.NewRequest(http.MethodPost, "/orders/mcp", brokenReader{})
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, request)
	var decoded map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &decoded)
	if failure, _ := decoded["error"].(map[string]any); failure == nil || failure["code"] != float64(-32600) {
		t.Fatalf("unreadable body = %d %s", recorder.Code, recorder.Body.String())
	}
}

// A query argument reaches the backend as a query string.
func TestMCPToolCallCarriesQueryArguments(t *testing.T) {
	st, _ := store.Open("", clock.New())
	defer func() { _ = st.Close() }()
	seen := []string{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.RequestURI())
		_, _ = w.Write([]byte("{}"))
	}))
	defer backend.Close()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	api, _ := st.UpsertAPI(model.API{
		ServiceID: service.ID(), Name: "orders", DisplayName: "Orders", Path: "orders",
		ServiceURL: backend.URL, IsCurrent: true,
		Document: map[string]any{"properties": map[string]any{"type": "mcp"}},
	})
	_, _ = st.UpsertOperation(model.Operation{
		APIID: api.ID(), Name: "list", DisplayName: "List", Method: http.MethodGet, URLTemplate: "/orders",
		Document: map[string]any{"properties": map[string]any{"request": map[string]any{
			"queryParameters": []any{map[string]any{"name": "expand", "type": "boolean"}},
		}}},
	})
	runtime := New("emulator", nil)
	if err := runtime.Activate(st, true); err != nil {
		t.Fatal(err)
	}
	mcpCall(t, runtime, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list","arguments":{"expand":true}}}`)
	if len(seen) != 1 || seen[0] != "/orders?expand=true" {
		t.Fatalf("the backend saw %v", seen)
	}
}

// The direct-call paths below are reachable only through inputs the store and
// the compiler will not produce, so they are exercised on the helper rather
// than by weakening a validation to reach them over HTTP.
func TestCallMCPBackendFailureModes(t *testing.T) {
	// An operation whose method is not a valid HTTP token cannot become a
	// request at all.
	if _, _, err := callMCPBackend(httptest.NewRequest(http.MethodGet, "/", nil), http.DefaultClient,
		"http://127.0.0.1", mcpc.ToolBinding{Method: "BAD METHOD", URLTemplate: "/x"}, "/x", "", nil); err == nil {
		t.Fatal("an invalid method was accepted")
	}
	// A response that promises more body than it delivers fails on read rather
	// than being reported as a successful empty answer.
	truncated := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "64")
		_, _ = w.Write([]byte("short"))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}))
	defer truncated.Close()
	if _, _, err := callMCPBackend(httptest.NewRequest(http.MethodGet, "/", nil), truncated.Client(),
		truncated.URL, mcpc.ToolBinding{Method: http.MethodGet, URLTemplate: "/x"}, "/x", "", nil); err == nil {
		t.Fatal("a truncated response body was accepted")
	}
}

// A tool whose backend was never configured is a failed tool, reported to the
// caller rather than swallowed.
func TestMCPMissingBackendIsAToolError(t *testing.T) {
	runtime, _ := mcpRuntime(t, map[string]any{"properties": map[string]any{"type": "mcp"}})
	snapshot := runtime.current.Load()
	for _, route := range snapshot.Services["emulator"].Routes {
		route.Plan.Inbound = append(route.Plan.Inbound, policy.Action{Kind: policy.ActionSetBackend, BackendID: "ghost"})
	}
	_, called := mcpCall(t, runtime, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get-order","arguments":{"orderId":"A-1"}}}`)
	if called["result"].(map[string]any)["isError"] != true {
		t.Fatalf("a missing backend was not reported: %v", called)
	}
}
