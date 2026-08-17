package expression

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
		"@(context.Api.Revision)",
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
	if _, err := EvalEnv("@(context.LastError.Reason)", Bind(Context{LastError: errors.New("temporary")})); err == nil {
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
		Product:      &NamedContext{Id: "starter", Name: "Starter"},
		Subscription: &NamedContext{Id: "sub-1", Name: "Dev"},
		User:         &NamedContext{Id: "ada", Name: "Ada"},
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
		"@(context.Product.Apis)",
		"@(context.Subscription.Key)",
		"@(context.User.Email)",
		"@(context.Deployment.Gateway)",
		"@(context.Api.Id)",
		"@(context.Operation.Name)",
		"@(context.Product.Name)",
		"@(context.Deployment.Region)",
	} {
		if _, err := EvalEnv(source, Bind(Context{})); err == nil {
			t.Fatalf("accepted %s on missing identity", source)
		}
	}
	for _, source := range []string{
		"@(context.Api.Revision)",
		"@(context.Operation.Url)",
		"@(context.Product.Apis)",
		"@(context.Subscription.Key)",
		"@(context.User.Email)",
		"@(context.Deployment.Gateway)",
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
