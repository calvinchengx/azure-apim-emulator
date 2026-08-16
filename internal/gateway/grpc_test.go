package gateway

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

const ordersProto = `
syntax = "proto3";
package shop.v1;
message Order { string ref = 1; }
message GetOrderRequest { string ref = 1; }
service Orders {
  rpc GetOrder(GetOrderRequest) returns (Order);
  rpc ListOrders(GetOrderRequest) returns (stream Order);
}
`

type grpcFixture struct {
	runtime *Runtime
	store   *store.Store
	backend *httptest.Server
	seen    *http.Request
}

// newGRPCFixture stands up a real cleartext HTTP/2 backend. A stubbed
// RoundTripper would not do: the gateway builds its own h2 transport for gRPC
// precisely because the default one will not, so a test that replaced the
// transport would be testing the stub rather than that decision.
func newGRPCFixture(t *testing.T, apiType, proto string, handler http.HandlerFunc) *grpcFixture {
	t.Helper()
	fixture := &grpcFixture{}
	backend := httptest.NewUnstartedServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.seen = r.Clone(r.Context())
		handler(w, r)
	}), &http2.Server{}))
	backend.Start()
	t.Cleanup(backend.Close)
	fixture.backend = backend

	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	fixture.store = st
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	if err != nil {
		t.Fatal(err)
	}
	document := map[string]any{"properties": map[string]any{}}
	if apiType != "" {
		document["properties"] = map[string]any{"apiType": apiType}
	}
	api, err := st.UpsertAPI(model.API{
		ServiceID: service.ID(), Name: "orders", DisplayName: "Orders", Path: "",
		ServiceURL: backend.URL, IsCurrent: true, Document: document,
	})
	if err != nil {
		t.Fatal(err)
	}
	if proto != "" {
		if _, err := st.UpsertAPISchema(model.APISchema{
			APIID: api.ID(), Name: "proto", ContentType: GRPCSchemaContentType,
			Document: map[string]any{"value": proto},
		}); err != nil {
			t.Fatal(err)
		}
	}
	fixture.runtime = New("emulator", &http.Client{})
	if err := fixture.runtime.Activate(st, true); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	return fixture
}

// call drives the gateway as an HTTP/2 gRPC client would.
func (f *grpcFixture) call(t *testing.T, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/grpc")
	request.Proto, request.ProtoMajor, request.ProtoMinor = "HTTP/2.0", 2, 0
	recorder := httptest.NewRecorder()
	f.runtime.ServeHTTP(recorder, request)
	return recorder
}

func okGRPCBackend(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("message-bytes"))
	w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
}

// The status lives in trailers, so a proxy that forwards only headers and body
// leaves the client waiting for a result that never comes.
func TestGRPCForwardsTrailersAndStatus(t *testing.T) {
	fixture := newGRPCFixture(t, "grpc", ordersProto, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("body"))
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "5")
		w.Header().Set(http.TrailerPrefix+"Grpc-Message", "no such order")
	})
	recorder := fixture.call(t, "/shop.v1.Orders/GetOrder", "request-bytes")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	// httptest.ResponseRecorder records what the handler WROTE; it does not
	// implement the trailer protocol a real server does, so a value set through
	// http.TrailerPrefix stays under the prefixed key here. Asserting the
	// prefixed key is asserting the thing this code controls. That the wire
	// delivery actually works is the witness's job, where grpc-js reads the
	// status out of real HTTP/2 trailers.
	if got := recorder.Header().Get(http.TrailerPrefix + "Grpc-Status"); got != "5" {
		t.Fatalf("Grpc-Status trailer = %q, want the backend's 5", got)
	}
	if got := recorder.Header().Get(http.TrailerPrefix + "Grpc-Message"); got != "no such order" {
		t.Fatalf("Grpc-Message trailer = %q", got)
	}
	if !strings.Contains(recorder.Header().Get("Trailer"), "Grpc-Status") {
		t.Fatalf("trailers must be announced before the body, got %q", recorder.Header().Get("Trailer"))
	}
	if body := recorder.Body.String(); body != "body" {
		t.Fatalf("body = %q", body)
	}
}

func TestGRPCReachesTheBackendOverHTTP2(t *testing.T) {
	fixture := newGRPCFixture(t, "grpc", ordersProto, okGRPCBackend)
	fixture.call(t, "/shop.v1.Orders/GetOrder", "request-bytes")
	if fixture.seen == nil {
		t.Fatal("the backend was never called")
	}
	// The whole reason grpcClient exists: Go's default transport speaks
	// HTTP/1.1 to a cleartext backend, and a gRPC server answers with HTTP/2
	// frames the transport then reports as a malformed response.
	if fixture.seen.ProtoMajor != 2 {
		t.Fatalf("backend saw %s; gRPC requires HTTP/2 on the outbound leg too", fixture.seen.Proto)
	}
	if got := fixture.seen.URL.Path; got != "/shop.v1.Orders/GetOrder" {
		t.Fatalf("backend path = %q, the method path must be preserved", got)
	}
	body, _ := io.ReadAll(fixture.seen.Body)
	_ = body
}

// Metadata is where gRPC puts auth and tracing, so it has to survive the hop.
func TestGRPCForwardsMetadataButNotHopByHopHeaders(t *testing.T) {
	fixture := newGRPCFixture(t, "grpc", ordersProto, okGRPCBackend)
	request := httptest.NewRequest(http.MethodPost, "/shop.v1.Orders/GetOrder", strings.NewReader("x"))
	request.Header.Set("Content-Type", "application/grpc")
	request.Header.Set("X-Caller", "witness")
	request.Header.Set("Connection", "keep-alive")
	request.Header.Set("Upgrade", "h2c")
	request.Proto, request.ProtoMajor, request.ProtoMinor = "HTTP/2.0", 2, 0
	fixture.runtime.ServeHTTP(httptest.NewRecorder(), request)

	if got := fixture.seen.Header.Get("X-Caller"); got != "witness" {
		t.Fatalf("metadata = %q, it must reach the backend", got)
	}
	// HTTP/2 forbids these outright, so forwarding them breaks the connection.
	for _, name := range []string{"Connection", "Upgrade"} {
		if got := fixture.seen.Header.Get(name); got != "" {
			t.Errorf("hop-by-hop header %s was forwarded as %q", name, got)
		}
	}
}

// Refused at the gateway with the status a real gRPC server uses, so the client
// cannot tell the difference, and the backend never sees the call.
func TestGRPCRefusesMethodsAbsentFromTheSchema(t *testing.T) {
	fixture := newGRPCFixture(t, "grpc", ordersProto, okGRPCBackend)
	recorder := fixture.call(t, "/shop.v1.Orders/Absent", "x")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d; a gRPC refusal is HTTP 200 with the code in Grpc-Status", recorder.Code)
	}
	if got := recorder.Header().Get("Grpc-Status"); got != grpcStatusUnimplemented {
		t.Fatalf("Grpc-Status = %q, want %s (UNIMPLEMENTED)", got, grpcStatusUnimplemented)
	}
	if fixture.seen != nil {
		t.Fatal("an unknown method must never reach the backend")
	}
}

// HTTP/1.1 cannot carry trailers, so a gRPC call over it can never be answered.
// Saying so beats proxying and leaving the client waiting forever.
func TestGRPCRefusesHTTP11(t *testing.T) {
	fixture := newGRPCFixture(t, "grpc", ordersProto, okGRPCBackend)
	request := httptest.NewRequest(http.MethodPost, "/shop.v1.Orders/GetOrder", strings.NewReader("x"))
	request.Header.Set("Content-Type", "application/grpc")
	recorder := httptest.NewRecorder()
	fixture.runtime.ServeHTTP(recorder, request)
	if got := recorder.Header().Get("Grpc-Status"); got != grpcStatusInternal {
		t.Fatalf("Grpc-Status = %q, want %s", got, grpcStatusInternal)
	}
	if !strings.Contains(recorder.Header().Get("Grpc-Message"), "HTTP/1.1") {
		t.Fatalf("the message must name the protocol that was negotiated, got %q", recorder.Header().Get("Grpc-Message"))
	}
	if fixture.seen != nil {
		t.Fatal("a call that cannot be answered must not reach the backend")
	}
}

func TestGRPCReportsAnUnreachableBackend(t *testing.T) {
	fixture := newGRPCFixture(t, "grpc", ordersProto, okGRPCBackend)
	fixture.backend.Close()
	recorder := fixture.call(t, "/shop.v1.Orders/GetOrder", "x")
	if got := recorder.Header().Get("Grpc-Status"); got != grpcStatusUnavailable {
		t.Fatalf("Grpc-Status = %q, want %s (UNAVAILABLE)", got, grpcStatusUnavailable)
	}
}

// A gRPC API is only gRPC when the apiType and the schema agree, and only gRPC
// TRAFFIC takes the gRPC path: a plain HTTP probe to the same API must not be
// framed as a gRPC response.
func TestGRPCNeedsBothSignalsAndTheRightContentType(t *testing.T) {
	if route := newGRPCFixture(t, "", ordersProto, okGRPCBackend).runtime.current.Load().Services["emulator"].Routes[0]; route.GRPC != nil {
		t.Error("a proto schema on a REST API must not put it on the gRPC path")
	}
	if route := newGRPCFixture(t, "grpc", "", okGRPCBackend).runtime.current.Load().Services["emulator"].Routes[0]; route.GRPC != nil {
		t.Error("a gRPC API with no schema yet must not be routable")
	}

	fixture := newGRPCFixture(t, "grpc", ordersProto, okGRPCBackend)
	plain := httptest.NewRequest(http.MethodPost, "/shop.v1.Orders/GetOrder", strings.NewReader("x"))
	plain.Proto, plain.ProtoMajor, plain.ProtoMinor = "HTTP/2.0", 2, 0
	recorder := httptest.NewRecorder()
	fixture.runtime.ServeHTTP(recorder, plain)
	if recorder.Header().Get("Grpc-Status") != "" {
		t.Fatal("a non-gRPC request must not be answered with a gRPC status")
	}
}

func TestGRPCActivationReportsABrokenSchema(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	api, _ := st.UpsertAPI(model.API{
		ServiceID: service.ID(), Name: "orders", DisplayName: "Orders", Path: "", ServiceURL: "http://backend.test",
		IsCurrent: true, Document: map[string]any{"properties": map[string]any{"apiType": "grpc"}},
	})
	if _, err := st.UpsertAPISchema(model.APISchema{
		APIID: api.ID(), Name: "proto", ContentType: GRPCSchemaContentType,
		Document: map[string]any{"value": "this is not protobuf"},
	}); err != nil {
		t.Fatal(err)
	}
	runtime := New("emulator", &http.Client{})
	if err := runtime.Activate(st, true); err == nil {
		t.Fatal("strict activation must reject an unparseable .proto")
	}
	// Non-strict is startup replay: the API degrades rather than taking every
	// other API down with it.
	if err := runtime.Activate(st, false); err != nil {
		t.Fatalf("non-strict activation must survive a broken schema: %v", err)
	}
	if route := runtime.current.Load().Services["emulator"].Routes[0]; route.GRPC != nil {
		t.Fatal("a schema that failed to compile must leave the route non-gRPC")
	}
	st.Close()
	if _, err := grpcSchemaFor(st, api); err == nil {
		t.Fatal("a store read failure must be reported")
	}
}

func TestGRPCSchemaLookupIgnoresOtherContentTypes(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	api, _ := st.UpsertAPI(model.API{
		ServiceID: service.ID(), Name: "orders", Path: "", IsCurrent: true,
		Document: map[string]any{"properties": map[string]any{"apiType": "grpc"}},
	})
	if _, err := st.UpsertAPISchema(model.APISchema{
		APIID: api.ID(), Name: "gql", ContentType: "application/vnd.ms-azure-apim.graphql.schema",
		Document: map[string]any{"value": "type Query { a: String }"},
	}); err != nil {
		t.Fatal(err)
	}
	schema, err := grpcSchemaFor(st, api)
	if err != nil || schema != nil {
		t.Fatalf("a GraphQL schema must not be compiled as protobuf, got %v %v", schema, err)
	}
}

func TestGRPCHelpers(t *testing.T) {
	if _, err := grpcBackendURL("", "/a/b", ""); err == nil {
		t.Fatal("a gRPC API with no backend URL has nowhere to forward")
	}
	got, err := grpcBackendURL("https://backend.test/", "/shop.v1.Orders/GetOrder", "x=1")
	if err != nil || got != "https://backend.test/shop.v1.Orders/GetOrder?x=1" {
		t.Fatalf("grpcBackendURL = %q %v", got, err)
	}

	// grpc-message is an HTTP header, so bytes it cannot hold are
	// percent-encoded. Sending them raw makes a strict HTTP/2 client reject the
	// whole response, turning a clear message into a protocol failure.
	if got := grpcPercentEncode("plain text"); got != "plain text" {
		t.Fatalf("printable ASCII must pass through, got %q", got)
	}
	if got := grpcPercentEncode("line\nbreak"); got != "line%0Abreak" {
		t.Fatalf("control characters must be encoded, got %q", got)
	}
	if got := grpcPercentEncode("100%"); got != "100%25" {
		t.Fatalf("the escape character itself must be encoded, got %q", got)
	}
	if got := grpcPercentEncode("héllo"); !strings.HasPrefix(got, "h%") {
		t.Fatalf("non-ASCII must be encoded, got %q", got)
	}

	if !isGRPCRequest(&http.Request{Header: http.Header{"Content-Type": {"application/grpc+proto"}}}) {
		t.Error("application/grpc+proto is gRPC traffic")
	}
	if isGRPCRequest(&http.Request{Header: http.Header{"Content-Type": {"application/json"}}}) {
		t.Error("JSON is not gRPC traffic")
	}
}

// A backend that never announces its trailers (the Trailers-Only reply) still
// has its status delivered, because grpc-status is announced regardless.
func TestTrailerNamesAlwaysIncludesTheStatus(t *testing.T) {
	names := trailerNames(&http.Response{Header: http.Header{}, Trailer: http.Header{}})
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "Grpc-Status") || !strings.Contains(joined, "Grpc-Message") {
		t.Fatalf("trailerNames = %v; the status must be announced even when the backend forgot", names)
	}
	declared := trailerNames(&http.Response{
		Header:  http.Header{"Trailer": {"X-One, X-Two", ""}},
		Trailer: http.Header{"X-Three": {"v"}},
	})
	for _, want := range []string{"X-One", "X-Two", "X-Three"} {
		if !strings.Contains(strings.Join(declared, ","), want) {
			t.Errorf("%s missing from %v", want, declared)
		}
	}
	// Announced twice, listed once.
	if strings.Count(strings.Join(trailerNames(&http.Response{
		Header:  http.Header{"Trailer": {"X-One"}},
		Trailer: http.Header{"X-One": {"v"}},
	}), ","), "X-One") != 1 {
		t.Error("a trailer named in both places must be announced once")
	}
}

func TestGRPCClientReusesAConfiguredTLSConfig(t *testing.T) {
	base := &http.Client{Transport: &http.Transport{TLSClientConfig: nil}}
	if client := grpcClient(base, "https://backend.test"); client.Transport == nil {
		t.Fatal("grpcClient must always produce a transport")
	}
	// A cleartext backend needs the h2c prior-knowledge handshake, which the
	// default transport will not do.
	plain := grpcClient(&http.Client{}, "http://backend.test")
	transport, ok := plain.Transport.(*http2.Transport)
	if !ok || !transport.AllowHTTP || transport.DialTLSContext == nil {
		t.Fatalf("a cleartext backend needs AllowHTTP and a plain dialer, got %+v", plain.Transport)
	}
	secure := grpcClient(&http.Client{Transport: &http.Transport{}}, "https://backend.test")
	if transport, ok := secure.Transport.(*http2.Transport); !ok || transport.AllowHTTP {
		t.Fatal("a TLS backend must not use the cleartext handshake")
	}
}

// A gRPC API with no backend URL has nowhere to forward. Reported as a status
// rather than a hang, which is what a client sees if the gateway stays silent.
func TestGRPCWithoutABackendURL(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	api, _ := st.UpsertAPI(model.API{
		ServiceID: service.ID(), Name: "orders", DisplayName: "Orders", Path: "", IsCurrent: true,
		Document: map[string]any{"properties": map[string]any{"apiType": "grpc"}},
	})
	if _, err := st.UpsertAPISchema(model.APISchema{
		APIID: api.ID(), Name: "proto", ContentType: GRPCSchemaContentType,
		Document: map[string]any{"value": ordersProto},
	}); err != nil {
		t.Fatal(err)
	}
	runtime := New("emulator", &http.Client{})
	if err := runtime.Activate(st, true); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/shop.v1.Orders/GetOrder", strings.NewReader("x"))
	request.Header.Set("Content-Type", "application/grpc")
	request.Proto, request.ProtoMajor, request.ProtoMinor = "HTTP/2.0", 2, 0
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, request)
	if got := recorder.Header().Get("Grpc-Status"); got != grpcStatusInternal {
		t.Fatalf("Grpc-Status = %q, want %s", got, grpcStatusInternal)
	}
}

// The per-backend transport is built at request time, so an undecodable client
// certificate fails there and must abort the call.
func TestGRPCReportsBackendClientFailures(t *testing.T) {
	fixture := newGRPCFixture(t, "grpc", ordersProto, okGRPCBackend)
	serviceID := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ApiManagement/service/emulator"
	if _, err := fixture.store.UpsertCertificate(model.Certificate{
		ServiceID: serviceID, Name: "client", Data: []byte("not a PKCS12 blob"), Password: "x",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.UpsertBackend(model.Backend{
		ServiceID: serviceID, Name: "secure", URL: fixture.backend.URL,
		Document: map[string]any{"properties": map[string]any{"credentials": map[string]any{"certificateIds": []any{"client"}}}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.UpsertPolicy(model.Policy{
		ScopeID: serviceID + "/apis/orders",
		Value:   `<policies><inbound><set-backend-service backend-id="secure" /></inbound></policies>`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.Activate(fixture.store, false); err != nil {
		t.Fatal(err)
	}
	fixture.seen = nil
	recorder := fixture.call(t, "/shop.v1.Orders/GetOrder", "x")
	if recorder.Code < 400 {
		t.Fatalf("an unusable backend certificate returned %d", recorder.Code)
	}
	if fixture.seen != nil {
		t.Fatal("no call may be forwarded when the transport cannot be built")
	}
}

// A client that disconnects mid-stream makes the write fail. Copying must stop
// rather than spin against a dead connection for the rest of the stream.
func TestCopyGRPCBodyStopsWhenTheClientGoesAway(t *testing.T) {
	written := 0
	copyGRPCBody(writerFunc(func(p []byte) (int, error) {
		written++
		return 0, io.ErrClosedPipe
	}), strings.NewReader(strings.Repeat("x", 1024)), nil)
	if written != 1 {
		t.Fatalf("wrote %d times after a failure; copying must stop at the first one", written)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestGRPCClientCarriesAConfiguredTLSConfig(t *testing.T) {
	base := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: "backend.test", MinVersion: tls.VersionTLS12}}}
	client := grpcClient(base, "https://backend.test")
	transport, ok := client.Transport.(*http2.Transport)
	if !ok || transport.TLSClientConfig == nil {
		t.Fatalf("transport = %+v; a configured TLS config must be carried onto the HTTP/2 transport", client.Transport)
	}
	if transport.TLSClientConfig.ServerName != "backend.test" {
		t.Fatalf("ServerName = %q; a backend requiring mutual TLS must keep working over gRPC", transport.TLSClientConfig.ServerName)
	}
}
