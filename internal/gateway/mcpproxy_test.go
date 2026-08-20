package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

// upstreamMCP stands in for an MCP server somebody else runs. It records what
// it was sent, so a test can assert the proxy forwarded rather than answered.
type upstreamMCP struct {
	requests []*http.Request
	bodies   []string
	server   *httptest.Server
}

func newUpstreamMCP(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, body string)) *upstreamMCP {
	t.Helper()
	upstream := &upstreamMCP{}
	upstream.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstream.requests = append(upstream.requests, r.Clone(r.Context()))
		upstream.bodies = append(upstream.bodies, string(body))
		handler(w, r, string(body))
	}))
	t.Cleanup(upstream.server.Close)
	return upstream
}

func passthroughRuntime(t *testing.T, upstreamURL string, mode string, policyXML string) *Runtime {
	t.Helper()
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	properties := map[string]any{"type": "mcp"}
	if mode != "" {
		properties["mcpMode"] = mode
	}
	api, err := st.UpsertAPI(model.API{
		ServiceID: service.ID(), Name: "proxy", DisplayName: "Proxy", Path: "proxy",
		ServiceURL: upstreamURL, IsCurrent: true,
		Document: map[string]any{"properties": properties},
	})
	if err != nil {
		t.Fatal(err)
	}
	if policyXML != "" {
		if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: policyXML}); err != nil {
			t.Fatal(err)
		}
	}
	runtime := New("emulator", nil)
	if err := runtime.Activate(st, true); err != nil {
		t.Fatal(err)
	}
	return runtime
}

func proxyRequest(t *testing.T, runtime *Runtime, method, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, "/proxy/mcp", reader)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, request)
	return recorder
}

// The tools belong to the upstream server. The proxy must forward the message
// rather than answer it, or an upstream implementing anything this emulator has
// never heard of would be silently capped at what it knows.
func TestMCPPassthroughForwardsEveryMessage(t *testing.T) {
	upstream := newUpstreamMCP(t, func(w http.ResponseWriter, r *http.Request, body string) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "upstream-session")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"upstream-only","inputSchema":{"type":"object"}}]}}`))
	})
	runtime := passthroughRuntime(t, upstream.server.URL, "passthrough", "")

	got := proxyRequest(t, runtime, http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json, text/event-stream",
	})
	if got.Code != http.StatusOK {
		t.Fatalf("status = %d %s", got.Code, got.Body.String())
	}
	// The upstream's own tool, which the emulator could not have synthesised: it
	// has no operations to synthesise from.
	if !strings.Contains(got.Body.String(), "upstream-only") {
		t.Fatalf("body = %s", got.Body.String())
	}
	// The session id the upstream assigns has to reach the client, or nothing
	// after initialize is accepted.
	if got.Header().Get("Mcp-Session-Id") != "upstream-session" {
		t.Fatalf("session id did not round-trip: %v", got.Header())
	}
	if len(upstream.bodies) != 1 || !strings.Contains(upstream.bodies[0], "tools/list") {
		t.Fatalf("upstream saw %v", upstream.bodies)
	}
	// Forwarded verbatim: a proxy that re-encoded the message could not carry a
	// method it does not know.
	if upstream.bodies[0] != `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` {
		t.Fatalf("the message was rewritten: %q", upstream.bodies[0])
	}
}

// MCP's transport lives in headers. Dropping either of these turns a working
// session into a client that reconnects forever.
func TestMCPPassthroughCarriesTheTransportHeaders(t *testing.T) {
	upstream := newUpstreamMCP(t, func(w http.ResponseWriter, r *http.Request, body string) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	})
	runtime := passthroughRuntime(t, upstream.server.URL, "passthrough", "")
	proxyRequest(t, runtime, http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, map[string]string{
		"Mcp-Session-Id":       "client-session",
		"Mcp-Protocol-Version": "2025-06-18",
		"Accept":               "application/json, text/event-stream",
	})
	if len(upstream.requests) != 1 {
		t.Fatalf("upstream saw %d requests", len(upstream.requests))
	}
	seen := upstream.requests[0].Header
	if seen.Get("Mcp-Session-Id") != "client-session" || seen.Get("Mcp-Protocol-Version") != "2025-06-18" {
		t.Fatalf("transport headers were dropped: %v", seen)
	}
	if !strings.Contains(seen.Get("Accept"), "text/event-stream") {
		t.Fatalf("Accept was not carried: %q", seen.Get("Accept"))
	}
}

// A long-running call streams. Buffering it would make a streaming tool look
// like a hung one.
func TestMCPPassthroughStreamsAnEventStream(t *testing.T) {
	upstream := newUpstreamMCP(t, func(w http.ResponseWriter, r *http.Request, body string) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"))
	})
	runtime := passthroughRuntime(t, upstream.server.URL, "passthrough", "")
	got := proxyRequest(t, runtime, http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`, map[string]string{
		"Accept": "application/json, text/event-stream",
	})
	if got.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("content type = %q", got.Header().Get("Content-Type"))
	}
	if got.Body.String() != "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n" {
		t.Fatalf("the stream was altered: %q", got.Body.String())
	}
}

// The GET that opens the server-to-client stream is forwarded too, because an
// upstream server may have messages to send even though a synthesised one never
// does. This is the case where the two modes must differ.
func TestMCPPassthroughForwardsTheServerStreamGET(t *testing.T) {
	upstream := newUpstreamMCP(t, func(w http.ResponseWriter, r *http.Request, body string) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(": keep-alive\n\n"))
	})
	runtime := passthroughRuntime(t, upstream.server.URL, "passthrough", "")
	got := proxyRequest(t, runtime, http.MethodGet, "", map[string]string{"Accept": "text/event-stream"})
	if got.Code != http.StatusOK {
		t.Fatalf("GET through the proxy = %d", got.Code)
	}
	if len(upstream.requests) != 1 || upstream.requests[0].Method != http.MethodGet {
		t.Fatalf("upstream saw %v", upstream.requests)
	}

	// A synthesised server declines the same GET, because it has nothing to
	// send. The two modes are only distinguishable here.
	synthesised := passthroughRuntime(t, upstream.server.URL, "", "")
	declined := proxyRequest(t, synthesised, http.MethodGet, "", map[string]string{"Accept": "text/event-stream"})
	if declined.Code != http.StatusMethodNotAllowed {
		t.Fatalf("a synthesised server did not decline the stream: %d", declined.Code)
	}
}

// The reason to put APIM in front of an MCP server at all: policies still run.
func TestMCPPassthroughRunsPolicies(t *testing.T) {
	upstream := newUpstreamMCP(t, func(w http.ResponseWriter, r *http.Request, body string) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	})
	runtime := passthroughRuntime(t, upstream.server.URL, "passthrough",
		`<policies><inbound><set-header name="X-Through-Apim" exists-action="override"><value>yes</value></set-header></inbound><outbound><set-header name="X-Proxied" exists-action="override"><value>yes</value></set-header></outbound></policies>`)
	got := proxyRequest(t, runtime, http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, nil)
	if upstream.requests[0].Header.Get("X-Through-Apim") != "yes" {
		t.Fatalf("the inbound policy did not run: %v", upstream.requests[0].Header)
	}
	if got.Header().Get("X-Proxied") != "yes" {
		t.Fatalf("the outbound policy did not run: %v", got.Header())
	}
}

// An upstream's own refusal reaches the caller as the upstream issued it. A
// gateway that softened it would hide a real protocol error.
func TestMCPPassthroughDoesNotSoftenUpstreamFailures(t *testing.T) {
	upstream := newUpstreamMCP(t, func(w http.ResponseWriter, r *http.Request, body string) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"no valid session"}}`))
	})
	runtime := passthroughRuntime(t, upstream.server.URL, "passthrough", "")
	got := proxyRequest(t, runtime, http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, nil)
	if got.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want the upstream's own 400", got.Code)
	}
	var decoded map[string]any
	_ = json.Unmarshal(got.Body.Bytes(), &decoded)
	if failure, _ := decoded["error"].(map[string]any); failure == nil || failure["message"] != "no valid session" {
		t.Fatalf("the upstream's error was rewritten: %s", got.Body.String())
	}
}

// An unreachable upstream is a gateway error, not a fabricated empty answer: a
// client told "no tools" would conclude the server has none.
func TestMCPPassthroughReportsAnUnreachableUpstream(t *testing.T) {
	runtime := passthroughRuntime(t, "http://127.0.0.1:0", "passthrough", "")
	got := proxyRequest(t, runtime, http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil)
	if got.Code != http.StatusBadGateway {
		t.Fatalf("unreachable upstream = %d %s", got.Code, got.Body.String())
	}
}

func TestMCPPassthroughModeDetection(t *testing.T) {
	if !isMCPPassthrough(map[string]any{"properties": map[string]any{"mcpMode": " PASSTHROUGH "}}) {
		t.Fatal("mode is not case- and space-insensitive")
	}
	for _, document := range []map[string]any{
		{}, {"properties": "scalar"},
		{"properties": map[string]any{}},
		{"properties": map[string]any{"mcpMode": "synthesized"}},
	} {
		if isMCPPassthrough(document) {
			t.Fatalf("%#v was read as passthrough", document)
		}
	}
	// A non-MCP API is never a passthrough, whatever it declares.
	upstream := newUpstreamMCP(t, func(w http.ResponseWriter, r *http.Request, body string) {})
	st, _ := store.Open("", clock.New())
	defer func() { _ = st.Close() }()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	_, _ = st.UpsertAPI(model.API{
		ServiceID: service.ID(), Name: "rest", DisplayName: "Rest", Path: "rest",
		ServiceURL: upstream.server.URL, IsCurrent: true,
		Document: map[string]any{"properties": map[string]any{"type": "http", "mcpMode": "passthrough"}},
	})
	runtime := New("emulator", nil)
	if err := runtime.Activate(st, true); err != nil {
		t.Fatal(err)
	}
	for _, route := range runtime.current.Load().Services["emulator"].Routes {
		if route.MCPPassthrough {
			t.Fatalf("a plain HTTP API was marked as an MCP passthrough")
		}
	}
}

// A backend the service does not define is a gateway error naming the backend,
// not a silent forward to nowhere.
func TestMCPPassthroughReportsAMissingBackend(t *testing.T) {
	upstream := newUpstreamMCP(t, func(w http.ResponseWriter, r *http.Request, body string) {})
	runtime := passthroughRuntime(t, upstream.server.URL, "passthrough", "")
	// Injected into the compiled plan rather than written as policy XML: the
	// compiler resolves backend references and refuses a dangling one, so this
	// state is unreachable through configuration and only worth guarding
	// against because the runtime cannot assume the compiler ran.
	for _, route := range runtime.current.Load().Services["emulator"].Routes {
		route.Plan.Inbound = append(route.Plan.Inbound, policy.Action{Kind: policy.ActionSetBackend, BackendID: "ghost"})
	}
	got := proxyRequest(t, runtime, http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, nil)
	if got.Code != http.StatusBadGateway || !strings.Contains(got.Body.String(), "ghost") {
		t.Fatalf("missing backend = %d %s", got.Code, got.Body.String())
	}
}

// An outbound policy may short-circuit the proxy entirely, and its response is
// what the caller gets. That is how a policy refuses an upstream answer rather
// than editing a stream it cannot safely edit.
func TestMCPPassthroughHonoursAnOutboundShortCircuit(t *testing.T) {
	upstream := newUpstreamMCP(t, func(w http.ResponseWriter, r *http.Request, body string) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"secret":"upstream"}}`))
	})
	runtime := passthroughRuntime(t, upstream.server.URL, "passthrough",
		`<policies><outbound><return-response><set-status code="403" reason="Blocked"/><set-body>refused by policy</set-body></return-response></outbound></policies>`)
	got := proxyRequest(t, runtime, http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, nil)
	if got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), "refused by policy") {
		t.Fatalf("short circuit = %d %s", got.Code, got.Body.String())
	}
	// The upstream's answer must not leak past the refusal.
	if strings.Contains(got.Body.String(), "upstream") {
		t.Fatalf("the upstream answer leaked through a refusal: %s", got.Body.String())
	}
}

// A policy that only changes the STATUS leaves the upstream's body alone, which
// is the case a short-circuit does not cover.
func TestMCPPassthroughHonoursAPolicyStatus(t *testing.T) {
	upstream := newUpstreamMCP(t, func(w http.ResponseWriter, r *http.Request, body string) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	})
	runtime := passthroughRuntime(t, upstream.server.URL, "passthrough",
		`<policies><outbound><set-status code="202" reason="Accepted"/></outbound></policies>`)
	got := proxyRequest(t, runtime, http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, nil)
	if got.Code != http.StatusAccepted {
		t.Fatalf("policy status = %d", got.Code)
	}
	if !strings.Contains(got.Body.String(), `"result"`) {
		t.Fatalf("the upstream body was lost: %s", got.Body.String())
	}
}

// A failing outbound policy is reported through the same error path as any
// other API's, rather than silently forwarding an unprocessed answer.
func TestMCPPassthroughReportsAnOutboundPolicyFailure(t *testing.T) {
	upstream := newUpstreamMCP(t, func(w http.ResponseWriter, r *http.Request, body string) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	})
	// An expression that compiles and cannot evaluate: there is no product on an
	// unsubscribed request, so reading through it fails at execution time.
	runtime := passthroughRuntime(t, upstream.server.URL, "passthrough",
		`<policies><outbound><set-header name="X-Product" exists-action="override"><value>@(context.Product.Name)</value></set-header></outbound></policies>`)
	got := proxyRequest(t, runtime, http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, nil)
	if got.Code < 400 {
		t.Fatalf("a failing outbound policy was not reported: %d %s", got.Code, got.Body.String())
	}
}

// A request the proxy cannot even build is a gateway error, not a panic.
func TestMCPPassthroughReportsAnUnbuildableRequest(t *testing.T) {
	upstream := newUpstreamMCP(t, func(w http.ResponseWriter, r *http.Request, body string) {})
	runtime := passthroughRuntime(t, upstream.server.URL+"\x7f", "passthrough", "")
	got := proxyRequest(t, runtime, http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, nil)
	if got.Code != http.StatusBadGateway {
		t.Fatalf("unbuildable request = %d %s", got.Code, got.Body.String())
	}
}
