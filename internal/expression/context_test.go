package expression

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRequestEnvBindings(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://api.example/match?x=1", nil)
	request.Header.Set("X-Test", "yes")
	request.RemoteAddr = "10.0.0.8:443"
	env := RequestEnv(request, map[string]string{"route": "blue"})

	cases := []struct {
		source string
		want   any
	}{
		{"@(context.Request.Method == 'POST')", true},
		{"@(context.Request.Url.Path == '/match')", true},
		{`@(context.Request.Url + "")`, "https://api.example/match?x=1"},
		{"@(context.Request.Url.Path)", "/match"},
		{"@(context.Request.Url.Host)", "api.example"},
		{"@(context.Request.Url.Scheme)", "https"},
		{"@(context.Request.Url.Query)", "x=1"},
		{"@(context.Request.Url.QueryString)", "?x=1"},
		{"@(context.Request.IpAddress)", "10.0.0.8"},
		{"@(context.Request.Headers['X-Test'])", "yes"},
		{"@(context.Request.Headers.Get('X-Test'))", "yes"},
		{"@(context.Request.Headers.Get('Missing'))", ""},
		{"@(context.Request.Headers.GetValueOrDefault('X-Test'))", "yes"},
		{"@(context.Request.Headers.GetValueOrDefault('Missing', 'fallback'))", "fallback"},
		{"@(context.Request.Headers.GetValueOrDefault('Missing'))", ""},
		{"@(context.Request.Url.Port)", int64(443)},
		{"@(context.Request.Body.AsString())", ""},
		{"@(context.Variables['route'])", "blue"},
		{"@(context.Variables.ContainsKey('route'))", true},
		{"@(context.Variables.ContainsKey('missing'))", false},
		{"@(context.Variables['missing'])", nil},
		{`@("hi".Length)`, int64(2)},
		{"@(42.ToString())", "42"},
	}
	for _, test := range cases {
		got, err := EvalEnv(test.source, env)
		if err != nil {
			t.Fatalf("%s: %v", test.source, err)
		}
		if got.Interface() != test.want {
			t.Fatalf("%s = %#v, want %#v", test.source, got.Interface(), test.want)
		}
	}
}

func TestRequestEnvFallbacksAndErrors(t *testing.T) {
	plain := httptest.NewRequest(http.MethodGet, "/plain", nil)
	plain.Host = ""
	plain.URL.Host = "from-url.example"
	plain.RemoteAddr = "192.0.2.1"
	got, err := EvalEnv("@(context.Request.Url.Host + context.Request.Url.Scheme + context.Request.Url.QueryString + context.Request.IpAddress + context.Request.Url.Port.ToString())", RequestEnv(plain, nil))
	if err != nil || got.String() != "from-url.examplehttp192.0.2.180" {
		t.Fatalf("plain request = %q %v", got, err)
	}
	relative, err := EvalEnv("@(context.Request.Url)", RequestEnv(plain, nil))
	if err != nil || relative.String() != "http://from-url.example/plain" {
		t.Fatalf("relative url = %q %v", relative, err)
	}

	secure := httptest.NewRequest(http.MethodGet, "/secure", nil)
	secure.TLS = &tls.ConnectionState{}
	scheme, err := EvalEnv("@(context.Request.Url.Scheme)", RequestEnv(secure, nil))
	if err != nil || scheme.String() != "https" {
		t.Fatalf("tls scheme = %q %v", scheme, err)
	}
	secureURL, err := EvalEnv("@(context.Request.Url)", RequestEnv(secure, nil))
	if err != nil || !strings.HasPrefix(secureURL.String(), "https://") {
		t.Fatalf("tls url = %q %v", secureURL, err)
	}
	tlsPort, err := EvalEnv("@(context.Request.Url.Port)", RequestEnv(secure, nil))
	if err != nil || tlsPort.Interface() != int64(443) {
		t.Fatalf("tls port = %+v %v", tlsPort, err)
	}

	explicit := httptest.NewRequest(http.MethodGet, "http://api.example:8080/match", nil)
	explicitPort, err := EvalEnv("@(context.Request.Url.Port)", RequestEnv(explicit, nil))
	if err != nil || explicitPort.Interface() != int64(8080) {
		t.Fatalf("explicit port = %+v %v", explicitPort, err)
	}
	hostPort := httptest.NewRequest(http.MethodGet, "/plain", nil)
	hostPort.Host = "from-host.example:9090"
	fromHost, err := EvalEnv("@(context.Request.Url.Port)", RequestEnv(hostPort, nil))
	if err != nil || fromHost.Interface() != int64(9090) {
		t.Fatalf("host port = %+v %v", fromHost, err)
	}
	invalidHostPort := httptest.NewRequest(http.MethodGet, "/plain", nil)
	invalidHostPort.Host = "from-host.example:abc"
	fallbackPort, err := EvalEnv("@(context.Request.Url.Port)", RequestEnv(invalidHostPort, nil))
	if err != nil || fallbackPort.Interface() != int64(80) {
		t.Fatalf("invalid host port = %+v %v", fallbackPort, err)
	}

	missingURL := &http.Request{Method: http.MethodGet}
	if _, err := EvalEnv("@(context.Request.Url.Path)", RequestEnv(missingURL, nil)); err == nil {
		t.Fatal("nil URL accepted")
	}
	emptyURL, err := EvalEnv("@(context.Request.Url)", RequestEnv(missingURL, nil))
	if err != nil || emptyURL.String() != "" {
		t.Fatalf("nil url string = %q %v", emptyURL, err)
	}

	nilRequest, err := EvalEnv("@(context.Request)", RequestEnv(nil, nil))
	if err != nil || !nilRequest.IsNull() {
		t.Fatalf("nil request = %+v %v", nilRequest, err)
	}
	if _, err := EvalEnv("@(context.Request.Method)", RequestEnv(nil, nil)); err == nil {
		t.Fatal("null request member accepted")
	}

	emptyVars, err := EvalEnv("@(context.Variables.ContainsKey('x') || context.Variables['x'] == null)", RequestEnv(plain, nil))
	if err != nil || !emptyVars.Truthy() {
		t.Fatalf("nil variables = %+v %v", emptyVars, err)
	}

	for _, source := range []string{
		"@(context.Missing)",
		"@(context.Api.Nonexistent)",
		"@(context.Request.Missing)",
		"@(context.Request.Body.AsJObject())",
		"@(context.Response.Body.AsJObject())",
		"@(context.LastError.Message)",
		"@(context.Request.Url.Fragment)",
		"@(context.Request.Headers.Missing)",
		"@(context.Request.Headers.Get())",
		"@(context.Request.Headers.Get(1))",
		"@(context.Request.Headers.Get('a', 'b'))",
		"@(context.Request.Headers[1])",
		"@(context.Request.Headers.GetValueOrDefault())",
		"@(context.Request.Headers.GetValueOrDefault(1))",
		"@(context.Request.Headers.GetValueOrDefault('a', 'b', 'c'))",
		"@(context.Request.Headers.GetValueOrDefault('a', (1 / 0)))",
		"@(context.Request.Headers[(1 / 0)])",
		"@(context.Variables[(1 / 0)])",
		"@(context.Variables[1])",
		"@(context.Variables.ContainsKey())",
		"@(context.Variables.ContainsKey(1))",
		"@(context.Variables.Missing)",
		"@(missing)",
		"@(42.Length)",
		"@(null.Foo)",
		"@(1[0])",
		"@(1())",
		"@(42.ToString(1))",
	} {
		if _, err := EvalEnv(source, RequestEnv(plain, map[string]string{"route": "blue"})); err == nil {
			t.Fatalf("accepted %s", source)
		}
	}
}

func TestResponseAndLastErrorBindings(t *testing.T) {
	response := &http.Response{
		StatusCode: http.StatusServiceUnavailable,
		Header:     http.Header{"X-Retry": {"yes"}},
	}
	env := Bind(Context{
		Request:   httptest.NewRequest(http.MethodGet, "/", nil),
		Response:  response,
		LastError: errors.New("temporary"),
	})
	cases := []struct {
		source string
		want   any
	}{
		{"@(context.Response.StatusCode)", int64(503)},
		{"@(context.Response.StatusCode >= 500)", true},
		{"@(context.Response.StatusReason)", "Service Unavailable"},
		{"@(context.Response.Headers['X-Retry'])", "yes"},
		{"@(context.LastError != null)", true},
		{"@(context.LastError.Message)", "temporary"},
	}
	for _, test := range cases {
		got, err := EvalEnv(test.source, env)
		if err != nil {
			t.Fatalf("%s: %v", test.source, err)
		}
		if got.Interface() != test.want {
			t.Fatalf("%s = %#v, want %#v", test.source, got.Interface(), test.want)
		}
	}

	named := &http.Response{StatusCode: http.StatusTeapot, Status: "418 I'm a teapot"}
	reason, err := EvalEnv("@(context.Response.StatusReason)", Bind(Context{Response: named}))
	if err != nil || reason.String() != "418 I'm a teapot" {
		t.Fatalf("named status = %q %v", reason, err)
	}

	missing, err := EvalEnv("@(context.Response == null && context.LastError == null)", Bind(Context{}))
	if err != nil || !missing.Truthy() {
		t.Fatalf("missing response/error = %+v %v", missing, err)
	}
	if _, err := EvalEnv("@(context.Response.StatusCode)", Bind(Context{})); err == nil {
		t.Fatal("null response member accepted")
	}
	if _, err := EvalEnv("@(context.Response.Missing)", env); err == nil {
		t.Fatal("unknown response member accepted")
	}
	// Reason is bound now. An error that carries no location reads it as empty
	// rather than failing: the member exists, this failure just has no
	// classification the engine could determine.
	if got, err := EvalEnv("@(context.LastError.Reason)", Bind(Context{LastError: errors.New("temporary")})); err != nil || got.String() != "" {
		t.Fatalf("unlocated reason = %q, %v", got.String(), err)
	}
	if _, err := EvalEnv("@(context.LastError.Nonexistent)", Bind(Context{LastError: errors.New("temporary")})); err == nil {
		t.Fatal("unknown last-error member accepted")
	}
	if _, err := EvalEnv("@(context.Response.Body.AsJObject())", env); err == nil {
		t.Fatal("unknown response body member accepted")
	}
}

func TestDeploymentContextBindings(t *testing.T) {
	env := Bind(Context{
		Api:          &ApiContext{Id: "pets", Name: "Pets API", Path: "pets"},
		Operation:    &OperationContext{Id: "get-pet", Name: "Get pet", Method: http.MethodGet, UrlTemplate: "/{id}"},
		Product:      &ProductContext{Id: "starter", Name: "Starter"},
		Subscription: &SubscriptionContext{Id: "sub-1", Name: "Dev"},
		User:         &UserContext{Id: "ada", Name: "Ada"},
		Deployment:   &DeploymentContext{ServiceName: "emulator", Region: "local"},
	})
	cases := []struct {
		source string
		want   any
	}{
		{"@(context.Api.Id)", "pets"},
		{"@(context.Api.Name)", "Pets API"},
		{"@(context.Api.Path)", "pets"},
		{"@(context.Operation.Id)", "get-pet"},
		{"@(context.Operation.Name)", "Get pet"},
		{"@(context.Operation.Method)", "GET"},
		{"@(context.Operation.UrlTemplate)", "/{id}"},
		{"@(context.Product.Id)", "starter"},
		{"@(context.Product.Name)", "Starter"},
		{"@(context.Subscription.Id)", "sub-1"},
		{"@(context.Subscription.Name)", "Dev"},
		{"@(context.User.Id)", "ada"},
		{"@(context.User.Name)", "Ada"},
		{"@(context.Deployment.ServiceName)", "emulator"},
		{"@(context.Deployment.Region)", "local"},
		{"@(context.Product != null)", true},
	}
	for _, test := range cases {
		got, err := EvalEnv(test.source, env)
		if err != nil {
			t.Fatalf("%s: %v", test.source, err)
		}
		if got.Interface() != test.want {
			t.Fatalf("%s = %#v, want %#v", test.source, got.Interface(), test.want)
		}
	}

	missing, err := EvalEnv("@(context.Api == null && context.Operation == null && context.Product == null && context.Subscription == null && context.User == null && context.Deployment == null)", Bind(Context{}))
	if err != nil || !missing.Truthy() {
		t.Fatalf("missing identities = %+v %v", missing, err)
	}
	for _, source := range []string{
		"@(context.Api.Revision)",
		"@(context.Operation.Url)",
		"@(context.Api.Id)",
		"@(context.Operation.Name)",
		"@(context.Product.Name)",
		"@(context.Deployment.Region)",
	} {
		if _, err := EvalEnv(source, Bind(Context{})); err == nil {
			t.Fatalf("accepted %s on missing identity", source)
		}
	}
	// Members that remain PLANNED. Api.Revision left this list when it was
	// bound; keeping a bound member here would have asserted the opposite of
	// what the ledger claims.
	for _, source := range []string{
		"@(context.Api.Nonexistent)",
		"@(context.Operation.Url)",
	} {
		if _, err := EvalEnv(source, env); err == nil {
			t.Fatalf("accepted %s", source)
		}
	}
}

func TestRequestAndResponseBodyAsString(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("payload"))
	got, err := EvalEnv("@(context.Request.Body.AsString())", RequestEnv(request, nil))
	if err != nil || got.String() != "payload" {
		t.Fatalf("request body = %q %v", got, err)
	}
	replay, err := request.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	replayed, _ := io.ReadAll(replay)
	if string(replayed) != "payload" {
		t.Fatalf("replayed request body = %q", replayed)
	}

	cached := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("ignored"))
	cached.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("cached")), nil
	}
	fromCache, err := EvalEnv("@(context.Request.Body.AsString())", RequestEnv(cached, nil))
	if err != nil || fromCache.String() != "cached" {
		t.Fatalf("GetBody = %q %v", fromCache, err)
	}

	emptyReq := httptest.NewRequest(http.MethodGet, "/", nil)
	emptyReq.Body = nil
	emptyReq.GetBody = nil
	empty, err := EvalEnv("@(context.Request.Body.AsString())", RequestEnv(emptyReq, nil))
	if err != nil || empty.String() != "" {
		t.Fatalf("empty request body = %q %v", empty, err)
	}
	nilBody, err := EvalEnv("@(context.Request.Body.AsString())", RequestEnv(&http.Request{Method: http.MethodGet}, nil))
	if err != nil || nilBody.String() != "" {
		t.Fatalf("nil request body = %q %v", nilBody, err)
	}
	if _, err := EvalEnv("@(context.Request.Missing)", RequestEnv(emptyReq, nil)); err == nil {
		t.Fatal("unknown request member accepted")
	}
	if _, err := EvalEnv("@(context.Response.Missing)", Bind(Context{Response: &http.Response{}})); err == nil {
		t.Fatal("unknown response member accepted")
	}

	response := &http.Response{Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}
	fromResponse, err := EvalEnv("@(context.Response.Body.AsString())", Bind(Context{Response: response}))
	if err != nil || fromResponse.String() != `{"ok":true}` {
		t.Fatalf("response body = %q %v", fromResponse, err)
	}
	second, _ := io.ReadAll(response.Body)
	if string(second) != `{"ok":true}` {
		t.Fatalf("replayed response body = %q", second)
	}

	noBody, err := EvalEnv("@(context.Response.Body.AsString())", Bind(Context{Response: &http.Response{}}))
	if err != nil || noBody.String() != "" {
		t.Fatalf("nil response body = %q %v", noBody, err)
	}

	if _, err := EvalEnv("@(context.Request.Body.AsString(1))", RequestEnv(request, nil)); err == nil {
		t.Fatal("AsString arity accepted")
	}
	if _, err := EvalEnv("@(context.Request.Body.AsJson())", RequestEnv(request, nil)); err == nil {
		t.Fatal("AsJson accepted")
	}
	if _, err := readRequestBody(nil); err != nil {
		t.Fatalf("nil request = %v", err)
	}
	if _, err := readResponseBody(nil); err != nil {
		t.Fatalf("nil response = %v", err)
	}

	failGet := httptest.NewRequest(http.MethodPost, "/", nil)
	failGet.GetBody = func() (io.ReadCloser, error) { return nil, errors.New("get body failed") }
	if _, err := EvalEnv("@(context.Request.Body.AsString())", RequestEnv(failGet, nil)); err == nil {
		t.Fatal("GetBody error accepted")
	}
	failRead := httptest.NewRequest(http.MethodPost, "/", nil)
	failRead.GetBody = func() (io.ReadCloser, error) { return errorReader{}, nil }
	if _, err := EvalEnv("@(context.Request.Body.AsString())", RequestEnv(failRead, nil)); err == nil {
		t.Fatal("GetBody read error accepted")
	}
	failBody := httptest.NewRequest(http.MethodPost, "/", nil)
	failBody.Body = errorReader{}
	if _, err := EvalEnv("@(context.Request.Body.AsString())", RequestEnv(failBody, nil)); err == nil {
		t.Fatal("request body read error accepted")
	}
	if _, err := EvalEnv("@(context.Response.Body.AsString())", Bind(Context{Response: &http.Response{Body: errorReader{}}})); err == nil {
		t.Fatal("response body read error accepted")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (errorReader) Close() error             { return nil }

func TestValueMembersIndexAndCall(t *testing.T) {
	host := Object(struct{}{})
	toString, err := host.member("ToString")
	if err != nil {
		t.Fatal(err)
	}
	text, err := toString.call(nil)
	if err != nil || text.String() != "" {
		t.Fatalf("object ToString = %+v %v", text, err)
	}
	if _, err := host.member("Missing"); err == nil {
		t.Fatal("unknown object member accepted")
	}
	if _, err := host.index(String("x")); err == nil {
		t.Fatal("non-indexable object accepted")
	}
	if _, err := host.call(nil); err == nil {
		t.Fatal("non-callable object accepted")
	}
	if _, err := Int(1).member("Missing"); err == nil {
		t.Fatal("unknown primitive member accepted")
	}
}

// The newly bound members, and the edges around them.
func TestBoundScalarMembersAndTheirEdges(t *testing.T) {
	env := Bind(Context{
		Api: &ApiContext{Id: "pets", Name: "Pets", Path: "pets", Revision: "3",
			Version: "v2", IsCurrentRevision: true, ServiceUrl: "https://backend.test"},
		Product: &ProductContext{Id: "starter", Name: "Starter", State: "published",
			ApprovalRequired: true, SubscriptionRequired: true, SubscriptionsLimit: Double(5)},
		Subscription: &SubscriptionContext{Id: "dev", Name: "Dev", Key: "presented",
			PrimaryKey: "primary", SecondaryKey: "secondary",
			CreatedDate: "2026-01-01T00:00:00Z", StartDate: "2026-01-02T00:00:00Z", EndDate: "2026-12-31T00:00:00Z"},
		Deployment: &DeploymentContext{ServiceName: "emulator", Region: "local",
			ServiceId: "/subscriptions/s/service/emulator", GatewayId: "edge",
			Gateway: &GatewayContext{Id: "edge", InstanceId: "edge-1", IsManaged: false, RegionName: "local"}},
		Timestamp: time.Date(2026, 8, 18, 9, 30, 0, 0, time.UTC),
		Elapsed:   func() time.Duration { return 1500 * time.Millisecond },
		RequestId: "req-7",
		Tracing:   true,
	})
	for _, test := range []struct{ source, want string }{
		{"@(context.Api.Revision)", "3"},
		{"@(context.Api.Version)", "v2"},
		{"@(context.Api.ServiceUrl)", "https://backend.test"},
		{"@(context.Product.State)", "published"},
		// The key a policy keys a limit by is the one THIS caller presented,
		// not the primary: two callers sharing a subscription must not collapse
		// into one bucket.
		{"@(context.Subscription.Key)", "presented"},
		{"@(context.Subscription.PrimaryKey)", "primary"},
		{"@(context.Subscription.CreatedDate)", "2026-01-01T00:00:00Z"},
		{"@(context.Subscription.EndDate)", "2026-12-31T00:00:00Z"},
		{"@(context.Deployment.ServiceId)", "/subscriptions/s/service/emulator"},
		{"@(context.Deployment.Gateway.InstanceId)", "edge-1"},
		{"@(context.Deployment.Gateway.RegionName)", "local"},
		{"@(context.Timestamp)", "2026-08-18T09:30:00Z"},
		// Rendered as .NET renders a TimeSpan, which is what a policy comparing
		// against a literal was written for.
		{"@(context.Elapsed)", "00:00:01.500"},
		{"@(context.RequestId)", "req-7"},
	} {
		got, err := EvalEnv(test.source, env)
		if err != nil || got.String() != test.want {
			t.Fatalf("%s = %q, %v; want %q", test.source, got.String(), err, test.want)
		}
	}
	for _, test := range []struct {
		source string
		want   bool
	}{
		{"@(context.Api.IsCurrentRevision)", true},
		{"@(context.Product.ApprovalRequired)", true},
		{"@(context.Product.SubscriptionRequired)", true},
		{"@(context.Tracing)", true},
		// A self-hosted gateway is not the managed one, which is the whole
		// reason a policy would test this.
		{"@(context.Deployment.Gateway.IsManaged)", false},
	} {
		got, err := EvalEnv(test.source, env)
		if err != nil || got.Truthy() != test.want {
			t.Fatalf("%s = %v, %v; want %v", test.source, got.Truthy(), err, test.want)
		}
	}
	// A product that sets a limit reports it as a number.
	if got, err := EvalEnv("@(context.Product.SubscriptionsLimit)", env); err != nil || got.String() != "5" {
		t.Fatalf("subscriptions limit = %q, %v", got.String(), err)
	}
	// Unknown members on the new hosts are refused rather than answered empty.
	for _, source := range []string{
		"@(context.Product.Nonexistent)",
		"@(context.Subscription.Nonexistent)",
		"@(context.Deployment.Gateway.Nonexistent)",
	} {
		if _, err := EvalEnv(source, env); err == nil {
			t.Fatalf("accepted %s", source)
		}
	}
}

// Outside a request there is no clock and no gateway, and `context` still binds
// so a literal expression can be evaluated. Those paths must answer rather than
// panic.
func TestScalarMembersOutsideARequest(t *testing.T) {
	env := Bind(Context{Deployment: &DeploymentContext{ServiceName: "emulator"}})
	// No Elapsed function: zero, not a nil dereference.
	if got, err := EvalEnv("@(context.Elapsed)", env); err != nil || got.String() != "00:00:00" {
		t.Fatalf("elapsed with no clock = %q, %v", got.String(), err)
	}
	// A deployment with no gateway reports null rather than an empty object,
	// so `context.Deployment.Gateway != null` reads correctly.
	if got, err := EvalEnv("@(context.Deployment.Gateway == null)", env); err != nil || !got.Truthy() {
		t.Fatalf("absent gateway = %v, %v", got.Truthy(), err)
	}
}

// A clock that has gone backwards renders as zero rather than a negative
// TimeSpan, which no policy comparison would handle.
func TestElapsedNeverRendersNegative(t *testing.T) {
	if got := formatElapsed(-5 * time.Second); got != "00:00:00.000" {
		t.Fatalf("negative elapsed = %q", got)
	}
	if got := formatElapsed(3*time.Hour + 4*time.Minute + 5*time.Second + 6*time.Millisecond); got != "03:04:05.006" {
		t.Fatalf("elapsed = %q", got)
	}
}

func TestRequestTimeMembers(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://api.example/orders/A-1?x=1", nil)
	leaf := testCertificate()

	// With no rewrite, OriginalUrl IS the current URL: returning null would
	// make a policy that logs it lose the common case.
	plain := Bind(Context{Request: request})
	if got, err := EvalEnv("@(context.Request.OriginalUrl.Path)", plain); err != nil || got.String() != "/orders/A-1" {
		t.Fatalf("original url with no rewrite = %q, %v", got.String(), err)
	}
	// A caller that presented no certificate reads null, which is what a policy
	// tests before reaching for a thumbprint.
	if got, err := EvalEnv("@(context.Request.Certificate == null)", plain); err != nil || !got.Truthy() {
		t.Fatalf("absent certificate = %v, %v", got.Truthy(), err)
	}

	rewritten := Bind(Context{
		Request:           request,
		OriginalUrl:       "https://api.example/original/path?y=2",
		MatchedParameters: map[string]string{"orderId": "A-1"},
	})
	// The ORIGINAL, not the rewritten one: a policy routing or logging on where
	// a request was aimed needs what the caller sent.
	if got, err := EvalEnv("@(context.Request.OriginalUrl.Path)", rewritten); err != nil || got.String() != "/original/path" {
		t.Fatalf("original url after rewrite = %q, %v", got.String(), err)
	}
	if got, err := EvalEnv(`@(context.Request.MatchedParameters["orderId"])`, rewritten); err != nil || got.String() != "A-1" {
		t.Fatalf("matched parameters = %q, %v", got.String(), err)
	}
	// A parameter the template never captured is empty rather than an error.
	if got, err := EvalEnv(`@(context.Request.MatchedParameters["absent"])`, rewritten); err != nil || got.String() != "" {
		t.Fatalf("absent parameter = %q, %v", got.String(), err)
	}
	// An unparsable original is reported rather than silently treated as absent.
	broken := Bind(Context{Request: request, OriginalUrl: "://nonsense"})
	if _, err := EvalEnv("@(context.Request.OriginalUrl.Path)", broken); err == nil {
		t.Fatal("an unparsable original url was accepted")
	}

	presented := request.Clone(request.Context())
	presented.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	withCert := Bind(Context{Request: presented})
	if got, err := EvalEnv("@(context.Request.Certificate.Subject)", withCert); err != nil || !strings.Contains(got.String(), "client.test") {
		t.Fatalf("client certificate subject = %q, %v", got.String(), err)
	}
}

func TestCertificateMembers(t *testing.T) {
	env := Bind(Context{Certificates: map[string]*x509.Certificate{"client": testCertificate()},
		Deployment: &DeploymentContext{ServiceName: "emulator"}})

	// The thumbprint is uppercase hex of the SHA-1, which is the form Azure
	// reports and the form a policy compares an uploaded certificate to.
	got, err := EvalEnv(`@(context.Deployment.Certificates["client"].Thumbprint)`, env)
	if err != nil || len(got.String()) != 40 || got.String() != strings.ToUpper(got.String()) {
		t.Fatalf("thumbprint = %q, %v", got.String(), err)
	}
	// Validity only: there is no trust store here, and answering true from a
	// chain nobody built would be the dangerous direction.
	if verified, err := EvalEnv(`@(context.Deployment.Certificates["client"].Verify())`, env); err != nil || !verified.Truthy() {
		t.Fatalf("verify = %v, %v", verified.Truthy(), err)
	}
	if _, err := EvalEnv(`@(context.Deployment.Certificates["client"].Verify("extra"))`, env); err == nil {
		t.Fatal("Verify accepted an argument")
	}
	if _, err := EvalEnv(`@(context.Deployment.Certificates["client"].Nonexistent)`, env); err == nil {
		t.Fatal("an unknown certificate member was accepted")
	}
	// A certificate nobody uploaded is null, not an error: a policy asking
	// whether one exists must be able to ask.
	if missing, err := EvalEnv(`@(context.Deployment.Certificates["absent"] == null)`, env); err != nil || !missing.Truthy() {
		t.Fatalf("absent certificate = %v, %v", missing.Truthy(), err)
	}
	if _, err := EvalEnv("@(context.Deployment.Certificates[1])", env); err == nil {
		t.Fatal("a non-string certificate key was accepted")
	}
	if _, err := EvalEnv("@(context.Deployment.Certificates.ContainsKey(1))", env); err == nil {
		t.Fatal("ContainsKey accepted a non-string")
	}
	if _, err := EvalEnv("@(context.Deployment.Certificates.Nonexistent)", env); err == nil {
		t.Fatal("an unknown certificates member was accepted")
	}
}

// An unknown member on the deployment host is refused, not answered empty.
func TestDeploymentRejectsUnknownMembers(t *testing.T) {
	env := Bind(Context{Deployment: &DeploymentContext{ServiceName: "emulator"}})
	if _, err := EvalEnv("@(context.Deployment.Nonexistent)", env); err == nil {
		t.Fatal("an unknown deployment member was accepted")
	}
}
