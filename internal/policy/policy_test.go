package policy

import (
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCompileAndExecute(t *testing.T) {
	plan, err := Compile(`<policies><inbound><base/><set-header name="X-Local" exists-action="override"><value>yes</value></set-header><rewrite-uri template="/rewritten"/></inbound><backend><forward-request/></backend><outbound><set-header name="X-Out"><value>done</value></set-header></outbound><on-error/></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "http://example/original", nil)
	state := &State{Request: request, Path: request.URL.Path}
	if err := Execute(plan.Inbound, state); err != nil {
		t.Fatal(err)
	}
	if request.Header.Get("X-Local") != "yes" || state.Path != "/rewritten" {
		t.Fatalf("unexpected state: %#v", state)
	}
	state.Response = &http.Response{Header: make(http.Header)}
	if err := Execute(plan.Outbound, state); err != nil {
		t.Fatal(err)
	}
	if state.Headers.Get("X-Out") != "done" {
		t.Fatalf("outbound header = %q", state.Headers.Get("X-Out"))
	}
}

func TestRetryPolicyCompilationAndExecution(t *testing.T) {
	plan, err := Compile(`<policies><backend><retry count="2" interval="0" condition="@(context.Response.StatusCode >= 500)"><set-backend-service base-url="https://retry.example"/><forward-request/></retry></backend></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Backend) != 1 || plan.Backend[0].Kind != ActionRetry || plan.Backend[0].RetryCount != 2 || len(plan.Backend[0].Children) != 2 || plan.Backend[0].Condition == "" {
		t.Fatalf("retry action = %+v", plan.Backend)
	}
	state := &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}
	if err := Execute(plan.Backend, state); err != nil {
		t.Fatal(err)
	}
	if state.BackendURL != "https://retry.example" {
		t.Fatalf("retry child execution state = %+v", state)
	}

	for name, xml := range map[string]string{
		"negative count":    `<policies><backend><retry count="-1"/></backend></policies>`,
		"invalid count":     `<policies><backend><retry count="bad"/></backend></policies>`,
		"negative interval": `<policies><backend><retry interval="-1"/></backend></policies>`,
		"invalid interval":  `<policies><backend><retry interval="bad"/></backend></policies>`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Compile(xml, false); err == nil {
				t.Fatal("invalid retry setting was accepted")
			}
		})
	}
	if _, err := Compile(`<policies><backend><retry><set-header name="X"><value>@(1)</value></set-header></retry></backend></policies>`, true); err == nil {
		t.Fatal("strict mode should reject unsupported retry child")
	}
	nonstrict, err := Compile(`<policies><backend><retry><set-header name="X"><value>@(1)</value></set-header></retry></backend></policies>`, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := Execute(nonstrict.Backend, state); err == nil {
		t.Fatal("unsupported retry child should fail during execution")
	}
}

func TestQueryParameterAndVariablePolicies(t *testing.T) {
	plan, err := Compile(`<policies><inbound><set-query-parameter name="new"><value>value</value></set-query-parameter><set-query-parameter name="existing" exists-action="skip"><value>replacement</value></set-query-parameter><set-query-parameter name="remove" exists-action="delete"/><set-variable name="route"><value>blue</value></set-variable></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://example/?existing=original&remove=yes", nil)
	state := &State{Request: request}
	if err := Execute(plan.Inbound, state); err != nil {
		t.Fatal(err)
	}
	query := request.URL.Query()
	if query.Get("new") != "value" || query.Get("existing") != "original" || query.Get("remove") != "" || state.Variables["route"] != "blue" {
		t.Fatalf("mutation state = query %v variables %v", query, state.Variables)
	}
	if err := Execute([]Action{{Kind: ActionSetQueryParameter, Name: "missing", Value: "added", Action: "skip"}}, state); err != nil || request.URL.Query().Get("missing") != "added" {
		t.Fatalf("skip missing parameter = %v, %v", request.URL.Query(), err)
	}
	if err := Execute([]Action{{Kind: ActionSetQueryParameter, Name: "x"}}, &State{}); err == nil {
		t.Fatal("query mutation without request should fail")
	}
	for _, value := range []string{
		`<policies><inbound><set-query-parameter name="x"><value>@(1)</value></set-query-parameter></inbound></policies>`,
		`<policies><inbound><set-variable name="x"><value>@(1)</value></set-variable></inbound></policies>`,
	} {
		if _, err := Compile(value, true); err == nil {
			t.Fatal("strict mode should reject expression mutation")
		}
	}
}

func TestSetBodyPolicy(t *testing.T) {
	plan, err := Compile(`<policies><inbound><set-body>request body</set-body></inbound><outbound><set-body><value>response body</value></set-body></outbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("old"))
	state := &State{Request: request}
	if err := Execute(plan.Inbound, state); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil || string(body) != "request body" || request.ContentLength != int64(len("request body")) {
		t.Fatalf("inbound body = %q, %v, length %d", body, err, request.ContentLength)
	}
	replayed, err := request.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	replayBody, err := io.ReadAll(replayed)
	if err != nil || string(replayBody) != "request body" {
		t.Fatalf("replayed body = %q, %v", replayBody, err)
	}
	state.Response = &http.Response{StatusCode: http.StatusOK}
	if err := Execute(plan.Outbound, state); err != nil {
		t.Fatal(err)
	}
	if !state.BodySet || state.Body != "response body" {
		t.Fatalf("outbound body = %+v", state)
	}
	if _, err := Compile(`<policies><inbound><set-body>@(context.Request.Body)</set-body></inbound></policies>`, true); err == nil {
		t.Fatal("strict mode should reject set-body expression")
	}
}

func TestCheckHeaderPolicy(t *testing.T) {
	plan, err := Compile(`<policies><inbound><check-header name="X-Role" ignore-case="true" failed-check-httpcode="403" failed-check-error-message="forbidden"><value>Admin</value><value>Operator</value></check-header></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	state := &State{Request: request}
	if err := Execute(plan.Inbound, state); err != nil || !state.Returned || state.StatusCode != http.StatusForbidden || state.Body != "forbidden" {
		t.Fatalf("failed check = %+v, %v", state, err)
	}
	request.Header.Set("X-Role", "operator")
	state = &State{Request: request}
	if err := Execute(plan.Inbound, state); err != nil || state.Returned {
		t.Fatalf("successful check = %+v, %v", state, err)
	}
	if _, err := Compile(`<policies><inbound><check-header name="X" failed-check-httpcode="bad"/></inbound></policies>`, false); err == nil {
		t.Fatal("invalid check-header status accepted")
	}
	if _, err := Compile(`<policies><inbound><check-header name="X"><unknown/></check-header></inbound></policies>`, true); err == nil {
		t.Fatal("unsupported check-header child accepted")
	}
	if _, err := Compile(`<policies><inbound><check-header name="X"><value>@(1)</value></check-header></inbound></policies>`, true); err == nil {
		t.Fatal("check-header expression accepted")
	}
	if err := Execute([]Action{{Kind: ActionCheckHeader, Name: "X"}}, &State{}); err == nil {
		t.Fatal("check-header without request should fail")
	}
}

func TestValidateJWTPolicy(t *testing.T) {
	plan, err := Compile(`<policies><inbound><validate-jwt failed-validation-httpcode="403" failed-validation-error-message="token rejected"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer good")
	state := &State{Request: request, ValidateToken: func(token string) error {
		if token != "good" {
			return errors.New("bad token")
		}
		return nil
	}}
	if err := Execute(plan.Inbound, state); err != nil || state.Returned {
		t.Fatalf("valid token = %+v, %v", state, err)
	}
	request.Header.Set("Authorization", "Bearer bad")
	state = &State{Request: request, ValidateToken: func(string) error { return errors.New("bad token") }}
	if err := Execute(plan.Inbound, state); err != nil || !state.Returned || state.StatusCode != http.StatusForbidden || state.Body != "token rejected" {
		t.Fatalf("invalid token = %+v, %v", state, err)
	}
	if _, err := Compile(`<policies><inbound><validate-jwt failed-validation-httpcode="bad"/></inbound></policies>`, false); err == nil {
		t.Fatal("invalid validate-jwt status accepted")
	}
	if err := Execute(plan.Inbound, &State{Request: request}); err == nil {
		t.Fatal("unconfigured validate-jwt accepted")
	}
}

func TestIPFilterPolicy(t *testing.T) {
	allow, err := Compile(`<policies><inbound><ip-filter action="allow" failed-check-error-message="blocked"><address>10.0.0.0/8</address><address>192.0.2.1</address></ip-filter></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	allowed := httptest.NewRequest(http.MethodGet, "/", nil)
	allowed.RemoteAddr = "10.1.2.3:1234"
	state := &State{Request: allowed}
	if err := Execute(allow.Inbound, state); err != nil || state.Returned {
		t.Fatalf("allowed IP = %+v, %v", state, err)
	}
	blocked := httptest.NewRequest(http.MethodGet, "/", nil)
	blocked.RemoteAddr = "203.0.113.5:1234"
	state = &State{Request: blocked}
	if err := Execute(allow.Inbound, state); err != nil || !state.Returned || state.StatusCode != http.StatusForbidden {
		t.Fatalf("blocked IP = %+v, %v", state, err)
	}
	forbid, err := Compile(`<policies><inbound><ip-filter action="forbid"><address>192.0.2.1</address></ip-filter></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := httptest.NewRequest(http.MethodGet, "/", nil)
	forbidden.RemoteAddr = "192.0.2.1:1234"
	state = &State{Request: forbidden}
	if err := Execute(forbid.Inbound, state); err != nil || !state.Returned {
		t.Fatalf("forbidden IP = %+v, %v", state, err)
	}
	for _, xml := range []string{
		`<policies><inbound><ip-filter action="bad"/></inbound></policies>`,
		`<policies><inbound><ip-filter action="allow"><range/></ip-filter></inbound></policies>`,
	} {
		if _, err := Compile(xml, true); err == nil {
			t.Fatal("invalid ip-filter accepted")
		}
	}
	if !ipMatches("192.0.2.1", "192.0.2.1") || ipMatches("not-an-ip", "192.0.2.1") || ipMatches("192.0.2.2", "bad/cidr") {
		t.Fatal("IP matcher mismatch")
	}
	if err := Execute([]Action{{Kind: ActionIPFilter, FilterAction: "allow"}}, &State{}); err == nil {
		t.Fatal("ip-filter without request should fail")
	}
}

func TestSetMethodAndCORSPolicies(t *testing.T) {
	plan, err := Compile(`<policies><inbound><set-method>POST</set-method><cors allowed-origins="https://app.example" allowed-methods="GET,POST" allowed-headers="Authorization" expose-headers="X-Request-ID" max-age="600" allow-credentials="true"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Origin", "https://app.example")
	state := &State{Request: request}
	if err := Execute(plan.Inbound, state); err != nil {
		t.Fatal(err)
	}
	if request.Method != http.MethodPost || state.Headers.Get("Access-Control-Allow-Origin") != "https://app.example" || state.Headers.Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("mutation/cors state = %+v", state)
	}
	preflight := httptest.NewRequest(http.MethodOptions, "/", nil)
	preflight.Header.Set("Origin", "https://app.example")
	state = &State{Request: preflight}
	if err := Execute(plan.Inbound[1:], state); err != nil || !state.Returned || state.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight state = %+v, %v", state, err)
	}
	if _, err := Compile(`<policies><inbound><set-method>@(context.Request.Method)</set-method></inbound></policies>`, true); err == nil {
		t.Fatal("set-method expression accepted")
	}
	if _, err := Compile(`<policies><inbound><cors allowed-origins="@(context.Request.Headers.GetValueOrDefault('Origin'))"/></inbound></policies>`, true); err == nil {
		t.Fatal("cors expression accepted")
	}
	noOrigin := httptest.NewRequest(http.MethodGet, "/", nil)
	state = &State{Request: noOrigin}
	if err := Execute([]Action{{Kind: ActionCORS}}, state); err != nil || state.Returned || len(state.Headers) != 0 {
		t.Fatalf("no-origin cors state = %+v, %v", state, err)
	}
	if err := Execute([]Action{{Kind: ActionSetMethod}}, &State{}); err == nil {
		t.Fatal("set-method without request should fail")
	}
	if err := Execute([]Action{{Kind: ActionCORS}}, &State{}); err == nil {
		t.Fatal("cors without request should fail")
	}
}

func TestSendRequestPolicy(t *testing.T) {
	plan, err := Compile(`<policies><inbound><send-request response-variable-name="probe"><set-url>https://probe.example/check</set-url><set-method>POST</set-method><set-header name="X-Probe"><value>yes</value></set-header><set-body>payload</set-body></send-request></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state := &State{Request: httptest.NewRequest(http.MethodGet, "/", nil), SendRequest: func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.String() != "https://probe.example/check" || request.Header.Get("X-Probe") != "yes" {
			t.Fatalf("probe request = %s %s %v", request.Method, request.URL, request.Header)
		}
		body, _ := io.ReadAll(request.Body)
		if string(body) != "payload" {
			t.Fatalf("probe body = %q", body)
		}
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader(""))}, nil
	}}
	if err := Execute(plan.Inbound, state); err != nil || state.Variables["probe"] != "204" {
		t.Fatalf("send-request state = %+v, %v", state, err)
	}
	valueBody, err := Compile(`<policies><inbound><send-request><set-url>https://probe.example</set-url><set-body><value>value-body</value></set-body></send-request></inbound></policies>`, true)
	if err != nil || len(valueBody.Inbound) != 1 || valueBody.Inbound[0].Body != "value-body" {
		t.Fatalf("value body action = %+v, %v", valueBody, err)
	}
	if err := Execute(valueBody.Inbound, &State{}); err == nil {
		t.Fatal("send-request without transport accepted")
	}
	invalid, err := Compile(`<policies><inbound><send-request><set-url>://bad</set-url></send-request></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := Execute(invalid.Inbound, &State{SendRequest: func(*http.Request) (*http.Response, error) { return nil, nil }}); err == nil {
		t.Fatal("invalid send-request URL accepted")
	}
	failed, err := Compile(`<policies><inbound><send-request><set-url>https://probe.example</set-url></send-request></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := Execute(failed.Inbound, &State{SendRequest: func(*http.Request) (*http.Response, error) { return nil, errors.New("probe failed") }}); err == nil {
		t.Fatal("send-request transport error lost")
	}
	for _, value := range []string{
		`<policies><inbound><send-request/></inbound></policies>`,
		`<policies><inbound><send-request><set-header name="X"><value>@(1)</value></set-header></send-request></inbound></policies>`,
		`<policies><inbound><send-request><set-url>https://probe.example</set-url><set-body>@(1)</set-body></send-request></inbound></policies>`,
		`<policies><inbound><send-request><set-url>https://probe.example</set-url><unknown/></send-request></inbound></policies>`,
	} {
		compiled, err := Compile(value, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := Execute(compiled.Inbound, &State{}); err == nil {
			t.Fatalf("expected send-request failure for %s", value)
		}
	}
}

func TestRateLimitPolicies(t *testing.T) {
	plan, err := Compile(`<policies><inbound><rate-limit-by-key calls="2" renewal-period="60" counter-key="client" retry-after-header-name="Retry-After"/></inbound></policies>`, true)
	if err != nil || len(plan.Inbound) != 1 || plan.Inbound[0].Kind != ActionRateLimit {
		t.Fatalf("rate-limit action = %+v, %v", plan, err)
	}
	state := &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}
	count := 0
	state.RateLimit = func(key string, calls int, period time.Duration) bool {
		if key != "client" || calls != 2 || period != time.Minute {
			t.Fatalf("limiter args = %q %d %s", key, calls, period)
		}
		count++
		return count > 2
	}
	if err := Execute(plan.Inbound, state); err != nil || state.Returned {
		t.Fatalf("first limit = %+v, %v", state, err)
	}
	if err := Execute(plan.Inbound, state); err != nil || state.Returned {
		t.Fatalf("second limit = %+v, %v", state, err)
	}
	if err := Execute(plan.Inbound, state); err != nil || !state.Returned || state.StatusCode != http.StatusTooManyRequests || state.Headers.Get("Retry-After") != "true" {
		t.Fatalf("limited request = %+v, %v", state, err)
	}
	for _, value := range []string{
		`<policies><inbound><rate-limit-by-key calls="0" renewal-period="1"/></inbound></policies>`,
		`<policies><inbound><quota-by-key calls="1" renewal-period="bad"/></inbound></policies>`,
		`<policies><inbound><quota-by-key calls="1" renewal-period="1" counter-key="@(1)"/></inbound></policies>`,
	} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid limit accepted: %s", value)
		}
	}
	if err := Execute(plan.Inbound, &State{}); err == nil {
		t.Fatal("rate-limit without limiter accepted")
	}
	emptyKey := &State{Request: httptest.NewRequest(http.MethodGet, "/", nil), RateLimit: func(key string, _ int, _ time.Duration) bool { return key == "127.0.0.1:0" }}
	emptyKey.Request.RemoteAddr = "127.0.0.1:0"
	if err := Execute([]Action{{Kind: ActionRateLimit, LimitCalls: 1, LimitPeriod: time.Minute, StatusCode: http.StatusTooManyRequests}}, emptyKey); err != nil || !emptyKey.Returned {
		t.Fatalf("empty counter key = %+v, %v", emptyKey, err)
	}
}

func TestCachePolicies(t *testing.T) {
	plan, err := Compile(`<policies><inbound><cache-lookup/></inbound><outbound><cache-store duration="60"/></outbound></policies>`, true)
	if err != nil || len(plan.Inbound) != 1 || len(plan.Outbound) != 1 {
		t.Fatalf("cache plan = %+v, %v", plan, err)
	}
	cache := map[string]struct {
		status  int
		headers http.Header
		body    string
	}{}
	state := &State{Request: httptest.NewRequest(http.MethodGet, "/", nil), CacheKey: "key", CacheGet: func(key string) (int, http.Header, string, bool) {
		value, ok := cache[key]
		return value.status, value.headers, value.body, ok
	}, CacheSet: func(key string, status int, headers http.Header, body string, _ time.Duration) {
		cache[key] = struct {
			status  int
			headers http.Header
			body    string
		}{status, headers, body}
	}}
	state.Response = &http.Response{StatusCode: http.StatusOK, Header: http.Header{"X-Cache": {"miss"}}, Body: io.NopCloser(strings.NewReader("body"))}
	if err := Execute(plan.Inbound, state); err != nil || state.Returned {
		t.Fatalf("cache miss = %+v, %v", state, err)
	}
	if err := Execute(plan.Outbound, state); err != nil || cache["key"].body != "body" {
		t.Fatalf("cache store = %+v, %v", cache, err)
	}
	hit := &State{Request: httptest.NewRequest(http.MethodGet, "/", nil), CacheKey: "key", CacheGet: state.CacheGet}
	if err := Execute(plan.Inbound, hit); err != nil || !hit.Returned || hit.StatusCode != http.StatusOK || hit.Body != "body" {
		t.Fatalf("cache hit = %+v, %v", hit, err)
	}
	for _, value := range []string{`<policies><outbound><cache-store duration="bad"/></outbound></policies>`, `<policies><outbound><cache-store/></outbound></policies>`} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid cache policy accepted: %s", value)
		}
	}
	if err := Execute(plan.Inbound, &State{}); err == nil {
		t.Fatal("cache lookup without cache accepted")
	}
	if err := Execute(plan.Outbound, &State{}); err == nil {
		t.Fatal("cache store without response accepted")
	}
	badBody := &State{Response: &http.Response{StatusCode: http.StatusOK, Body: errorBody{}}, CacheSet: func(string, int, http.Header, string, time.Duration) {}}
	if err := Execute(plan.Outbound, badBody); err == nil {
		t.Fatal("cache body read error lost")
	}
}

func TestValidateStatusCodePolicy(t *testing.T) {
	plan, err := Compile(`<policies><outbound><validate-status-code unspecified-code-action="prevent" errors-variable-name="status"><status-code-range min="200" max="299"/></validate-status-code></outbound></policies>`, true)
	if err != nil || len(plan.Outbound) != 1 || plan.Outbound[0].Kind != ActionValidateStatus {
		t.Fatalf("validation plan = %+v, %v", plan, err)
	}
	state := &State{Response: &http.Response{StatusCode: http.StatusOK}, Variables: map[string]string{}}
	if err := Execute(plan.Outbound, state); err != nil || state.Returned {
		t.Fatalf("valid status = %+v, %v", state, err)
	}
	state = &State{Response: &http.Response{StatusCode: http.StatusInternalServerError}, Variables: map[string]string{}}
	if err := Execute(plan.Outbound, state); err != nil || !state.Returned || state.StatusCode != http.StatusBadGateway || state.Variables["status"] != "500" {
		t.Fatalf("invalid status = %+v, %v", state, err)
	}
	ignore, err := Compile(`<policies><outbound><validate-status-code unspecified-code-action="ignore"><status-code-range min="200" max="299"/></validate-status-code></outbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state = &State{Response: &http.Response{StatusCode: http.StatusInternalServerError}}
	if err := Execute(ignore.Outbound, state); err != nil || state.Returned {
		t.Fatalf("ignored status = %+v, %v", state, err)
	}
	for _, value := range []string{
		`<policies><outbound><validate-status-code><status-code-range min="bad"/></validate-status-code></outbound></policies>`,
		`<policies><outbound><validate-status-code><status-code-range max="bad"/></validate-status-code></outbound></policies>`,
		`<policies><outbound><validate-status-code><status-code-range min="500" max="200"/></validate-status-code></outbound></policies>`,
		`<policies><outbound><validate-status-code><unknown/></validate-status-code></outbound></policies>`,
	} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid status validation accepted: %s", value)
		}
	}
	if err := Execute(plan.Outbound, &State{}); err == nil {
		t.Fatal("status validation without response accepted")
	}
	withoutVariables := &State{Response: &http.Response{StatusCode: http.StatusInternalServerError}}
	if err := Execute(plan.Outbound, withoutVariables); err != nil || !withoutVariables.Returned || withoutVariables.Variables["status"] != "500" {
		t.Fatalf("status variables = %+v, %v", withoutVariables, err)
	}
}

func TestValidateContentPolicy(t *testing.T) {
	plan, err := Compile(`<policies><inbound><validate-content max-size="4" size-exceeded-action="prevent"><content type="application/json"/></validate-content></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
	request.Header.Set("Content-Type", "application/json")
	state := &State{Request: request}
	if err := Execute(plan.Inbound, state); err != nil || state.Returned {
		t.Fatalf("valid content = %+v, %v", state, err)
	}
	value, _ := io.ReadAll(request.Body)
	if string(value) != "{}" {
		t.Fatalf("body replay = %q", value)
	}
	request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader("toolong"))
	request.Header.Set("Content-Type", "text/plain")
	state = &State{Request: request}
	if err := Execute(plan.Inbound, state); err != nil || !state.Returned || state.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid content = %+v, %v", state, err)
	}
	ignore, err := Compile(`<policies><outbound><validate-content max-size="1" size-exceeded-action="ignore"/></outbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state = &State{Response: &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("long"))}}
	if err := Execute(ignore.Outbound, state); err != nil || state.Returned {
		t.Fatalf("ignored content = %+v, %v", state, err)
	}
	for _, value := range []string{`<policies><inbound><validate-content max-size="bad"/></inbound></policies>`, `<policies><inbound><validate-content size-exceeded-action="bad"/></inbound></policies>`, `<policies><inbound><validate-content><unknown/></validate-content></inbound></policies>`} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid content policy accepted: %s", value)
		}
	}
	if _, err := Compile(`<policies><inbound><validate-content><content type="application/json" action="bad"/></validate-content></inbound></policies>`, true); err == nil {
		t.Fatal("invalid content action accepted")
	}
	if err := Execute(plan.Inbound, &State{}); err == nil {
		t.Fatal("content validation without request accepted")
	}
	badBody := &State{Request: httptest.NewRequest(http.MethodPost, "/", nil)}
	badBody.Request.Body = errorBody{}
	if err := Execute(plan.Inbound, badBody); err == nil {
		t.Fatal("content body read error lost")
	}
}

func TestValidateHeadersPolicy(t *testing.T) {
	plan, err := Compile(`<policies><inbound><validate-headers specified-header-action="prevent" unspecified-header-action="ignore"><header name="X-Mode"><value>strict</value></header></validate-headers></inbound></policies>`, true)
	if err != nil || len(plan.Inbound) != 1 || plan.Inbound[0].Kind != ActionValidateHeaders {
		t.Fatalf("header validation plan = %+v, %v", plan, err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Mode", "strict")
	request.Header.Set("X-Extra", "ignored")
	state := &State{Request: request}
	if err := Execute(plan.Inbound, state); err != nil || state.Returned {
		t.Fatalf("valid header = %+v, %v", state, err)
	}
	request.Header.Set("X-Mode", "loose")
	state = &State{Request: request}
	if err := Execute(plan.Inbound, state); err != nil || !state.Returned || state.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid header = %+v, %v", state, err)
	}
	ignoreRule, err := Compile(`<policies><inbound><validate-headers><header name="X-Mode" action="ignore"/></validate-headers></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state = &State{Request: request}
	if err := Execute(ignoreRule.Inbound, state); err != nil || state.Returned {
		t.Fatalf("ignored header = %+v, %v", state, err)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	state = &State{Request: request}
	if err := Execute(plan.Inbound, state); err != nil || !state.Returned {
		t.Fatalf("missing header = %+v, %v", state, err)
	}
	ignore, err := Compile(`<policies><outbound><validate-headers specified-header-action="ignore" unspecified-header-action="prevent"><header name="X-Mode"><value>strict</value></header></validate-headers></outbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	response := &http.Response{Header: http.Header{"X-Other": []string{"value"}}}
	state = &State{Response: response}
	if err := Execute(ignore.Outbound, state); err != nil || !state.Returned {
		t.Fatalf("unspecified header = %+v, %v", state, err)
	}
	for _, value := range []string{
		`<policies><inbound><validate-headers specified-header-action="bad"/></inbound></policies>`,
		`<policies><inbound><validate-headers><header name="X" action="bad"/></validate-headers></inbound></policies>`,
		`<policies><inbound><validate-headers><unknown/></validate-headers></inbound></policies>`,
		`<policies><inbound><validate-headers><header name="X"><unknown/></header></validate-headers></inbound></policies>`,
	} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid header validation accepted: %s", value)
		}
	}
	if err := Execute(plan.Inbound, &State{}); err == nil {
		t.Fatal("header validation without request accepted")
	}
}

func TestValidateParametersPolicy(t *testing.T) {
	plan, err := Compile(`<policies><inbound><validate-parameters specified-parameter-action="prevent" unspecified-parameter-action="ignore"><parameter name="mode"><value>strict</value></parameter></validate-parameters></inbound></policies>`, true)
	if err != nil || len(plan.Inbound) != 1 || plan.Inbound[0].Kind != ActionValidateParameters {
		t.Fatalf("parameter validation plan = %+v, %v", plan, err)
	}
	request := httptest.NewRequest(http.MethodGet, "/?mode=strict&extra=value", nil)
	state := &State{Request: request}
	if err := Execute(plan.Inbound, state); err != nil || state.Returned {
		t.Fatalf("valid parameter = %+v, %v", state, err)
	}
	request = httptest.NewRequest(http.MethodGet, "/?mode=loose", nil)
	state = &State{Request: request}
	if err := Execute(plan.Inbound, state); err != nil || !state.Returned || state.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid parameter = %+v, %v", state, err)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	state = &State{Request: request}
	if err := Execute(plan.Inbound, state); err != nil || !state.Returned {
		t.Fatalf("missing parameter = %+v, %v", state, err)
	}
	ignore, err := Compile(`<policies><inbound><validate-parameters specified-parameter-action="ignore" unspecified-parameter-action="prevent"><parameter name="mode"><value>strict</value></parameter></validate-parameters></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state = &State{Request: httptest.NewRequest(http.MethodGet, "/?other=value", nil)}
	if err := Execute(ignore.Inbound, state); err != nil || !state.Returned {
		t.Fatalf("unspecified parameter = %+v, %v", state, err)
	}
	valueIgnore, err := Compile(`<policies><inbound><validate-parameters><parameter name="mode" action="ignore"><value>strict</value></parameter></validate-parameters></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state = &State{Request: httptest.NewRequest(http.MethodGet, "/?mode=loose", nil)}
	if err := Execute(valueIgnore.Inbound, state); err != nil || state.Returned {
		t.Fatalf("ignored parameter value = %+v, %v", state, err)
	}
	for _, value := range []string{
		`<policies><inbound><validate-parameters specified-parameter-action="bad"/></inbound></policies>`,
		`<policies><inbound><validate-parameters><parameter name="mode" action="bad"/></validate-parameters></inbound></policies>`,
		`<policies><inbound><validate-parameters><unknown/></validate-parameters></inbound></policies>`,
		`<policies><inbound><validate-parameters><parameter name="mode"><unknown/></parameter></validate-parameters></inbound></policies>`,
	} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid parameter validation accepted: %s", value)
		}
	}
	if err := Execute(plan.Inbound, &State{}); err == nil {
		t.Fatal("parameter validation without request accepted")
	}
}

func TestValidateClientCertificatePolicy(t *testing.T) {
	certificate := &x509.Certificate{Raw: []byte("client-certificate")}
	thumbprint := strings.ToUpper(fmt.Sprintf("%X", sha1.Sum(certificate.Raw)))
	plan, err := Compile(`<policies><inbound><validate-client-certificate><identities><identity thumbprint="`+thumbprint+`"/></identities></validate-client-certificate></inbound></policies>`, true)
	if err != nil || len(plan.Inbound) != 1 || plan.Inbound[0].Kind != ActionValidateClientCertificate {
		t.Fatalf("client certificate plan = %+v, %v", plan, err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	state := &State{Request: request}
	if err := Execute(plan.Inbound, state); err != nil || state.Returned {
		t.Fatalf("valid client certificate = %+v, %v", state, err)
	}
	request.TLS.PeerCertificates = []*x509.Certificate{{Raw: []byte("other")}}
	state = &State{Request: request}
	if err := Execute(plan.Inbound, state); err != nil || !state.Returned || state.StatusCode != http.StatusForbidden {
		t.Fatalf("invalid client certificate = %+v, %v", state, err)
	}
	state = &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}
	if err := Execute(plan.Inbound, state); err != nil || !state.Returned {
		t.Fatalf("missing client certificate = %+v, %v", state, err)
	}
	for _, value := range []string{
		`<policies><inbound><validate-client-certificate><unknown/></validate-client-certificate></inbound></policies>`,
		`<policies><inbound><validate-client-certificate><identities><identity/></identities></validate-client-certificate></inbound></policies>`,
	} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid client certificate policy accepted: %s", value)
		}
	}
	if err := Execute(plan.Inbound, &State{}); err != nil {
		t.Fatalf("client certificate state error = %v", err)
	}
}

func TestChoosePolicy(t *testing.T) {
	plan, err := Compile(`<policies><inbound><choose><when condition="@(context.Request.Method == 'GET')"><set-header name="X-Branch"><value>get</value></set-header></when><otherwise><set-header name="X-Branch"><value>other</value></set-header></otherwise></choose></inbound></policies>`, true)
	if err != nil || len(plan.Inbound) != 1 || plan.Inbound[0].Kind != ActionChoose {
		t.Fatalf("choose plan = %+v, %v", plan, err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	state := &State{Request: request}
	if err := Execute(plan.Inbound, state); err != nil || request.Header.Get("X-Branch") != "get" {
		t.Fatalf("when branch = %+v, %v", state, err)
	}
	request = httptest.NewRequest(http.MethodPost, "/", nil)
	state = &State{Request: request}
	if err := Execute(plan.Inbound, state); err != nil || request.Header.Get("X-Branch") != "other" {
		t.Fatalf("otherwise branch = %+v, %v", state, err)
	}
	truePlan, err := Compile(`<policies><inbound><choose><when condition="true"><set-variable name="picked"><value>yes</value></set-variable></when><when condition="false"><set-variable name="picked"><value>no</value></set-variable></when></choose></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state = &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}
	if err := Execute(truePlan.Inbound, state); err != nil || state.Variables["picked"] != "yes" {
		t.Fatalf("literal choose = %+v, %v", state, err)
	}
	falsePlan, err := Compile(`<policies><inbound><choose><when condition="false"><set-variable name="picked"><value>no</value></set-variable></when></choose></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state = &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}
	if err := Execute(falsePlan.Inbound, state); err != nil || state.Variables != nil {
		t.Fatalf("false choose = %+v, %v", state, err)
	}
	pathPlan, err := Compile(`<policies><inbound><choose><when condition="@(context.Request.Url.Path == '/match')"><set-variable name="picked"><value>path</value></set-variable></when></choose></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state = &State{Request: httptest.NewRequest(http.MethodGet, "/match", nil)}
	if err := Execute(pathPlan.Inbound, state); err != nil || state.Variables["picked"] != "path" {
		t.Fatalf("path choose = %+v, %v", state, err)
	}
	returned := &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}
	if err := Execute([]Action{{Kind: ActionChoose, Branches: []ChooseBranch{{Condition: "true", Actions: []Action{{Kind: ActionReturnResponse, StatusCode: http.StatusTeapot}}}}}}, returned); err != nil || !returned.Returned {
		t.Fatalf("returned choose = %+v, %v", returned, err)
	}
	if err := Execute([]Action{{Kind: ActionChoose, Branches: []ChooseBranch{{Condition: "true", Actions: []Action{{Kind: ActionUnsupported, Source: "bad"}}}}}}, &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}); err == nil {
		t.Fatal("choose child error lost")
	}
	if err := Execute([]Action{{Kind: ActionChoose, Branches: []ChooseBranch{{Condition: "@(context.Request.Method == 'GET')", Actions: nil}}}}, &State{}); err == nil {
		t.Fatal("choose condition request error lost")
	}
	for _, value := range []string{
		`<policies><inbound><choose><when><set-variable name="x"><value>y</value></set-variable></when></choose></inbound></policies>`,
		`<policies><inbound><choose><otherwise/><otherwise/></choose></inbound></policies>`,
		`<policies><inbound><choose><unknown/></choose></inbound></policies>`,
		`<policies><inbound><choose><when condition="true"><unknown/></when></choose></inbound></policies>`,
		`<policies><inbound><choose><when condition="true"/><otherwise><unknown/></otherwise></choose></inbound></policies>`,
	} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid choose accepted: %s", value)
		}
	}
	unsupportedPlan, err := Compile(`<policies><inbound><choose><when condition="@(context.Request.Headers.Get('X') == 'yes')"/></choose></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := Execute(unsupportedPlan.Inbound, &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}); err == nil {
		t.Fatal("unsupported choose condition accepted")
	}
	invalidComparison, err := Compile(`<policies><inbound><choose><when condition="@(true)"><set-variable name="x"><value>y</value></set-variable></when></choose></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	invalidComparison.Inbound[0].Branches[0].Condition = "context.Request.Method"
	if err := Execute(invalidComparison.Inbound, &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}); err == nil {
		t.Fatal("invalid choose comparison accepted")
	}
}

func TestTracePolicy(t *testing.T) {
	plan, err := Compile(`<policies><inbound><trace source="policy" severity="information"><message>hello</message></trace></inbound></policies>`, true)
	if err != nil || len(plan.Inbound) != 1 || plan.Inbound[0].Kind != ActionTrace {
		t.Fatalf("trace plan = %+v, %v", plan, err)
	}
	var phase, detail string
	state := &State{Trace: func(gotPhase, gotDetail string) { phase, detail = gotPhase, gotDetail }}
	if err := Execute(plan.Inbound, state); err != nil || phase != "policy" || detail != "policy information hello" {
		t.Fatalf("trace event = %q %q, %v", phase, detail, err)
	}
	if err := Execute(plan.Inbound, &State{}); err != nil {
		t.Fatalf("trace without sink = %v", err)
	}
	if _, err := Compile(`<policies><inbound><trace><unknown/></trace></inbound></policies>`, true); err == nil {
		t.Fatal("invalid trace accepted")
	}
}

func TestAuthenticationBasicPolicy(t *testing.T) {
	plan, err := Compile(`<policies><backend><authentication-basic username="user" password="secret"/></backend></policies>`, true)
	if err != nil || len(plan.Backend) != 1 || plan.Backend[0].Kind != ActionAuthenticationBasic {
		t.Fatalf("authentication plan = %+v, %v", plan, err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	state := &State{Request: request}
	if err := Execute(plan.Backend, state); err != nil || request.Header.Get("Authorization") != "Basic dXNlcjpzZWNyZXQ=" {
		t.Fatalf("authentication header = %q, %v", request.Header.Get("Authorization"), err)
	}
	if err := Execute(plan.Backend, &State{}); err == nil {
		t.Fatal("authentication without request accepted")
	}
	for _, value := range []string{
		`<policies><backend><authentication-basic username="" password="secret"/></backend></policies>`,
		`<policies><backend><authentication-basic username="@(context.Variables['user'])" password="secret"/></backend></policies>`,
		`<policies><backend><authentication-basic username="user" password="secret"><unknown/></authentication-basic></backend></policies>`,
	} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid authentication policy accepted: %s", value)
		}
	}
}

func TestAuthenticationManagedIdentityPolicy(t *testing.T) {
	plan, err := Compile(`<policies><backend><authentication-managed-identity resource="https://backend.test"/></backend></policies>`, true)
	if err != nil || len(plan.Backend) != 1 || plan.Backend[0].Kind != ActionAuthenticationManagedIdentity {
		t.Fatalf("managed identity plan = %+v, %v", plan, err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	state := &State{Request: request, AcquireToken: func(resource string) (string, error) {
		if resource != "https://backend.test" {
			t.Fatalf("resource = %q", resource)
		}
		return "token", nil
	}}
	if err := Execute(plan.Backend, state); err != nil || request.Header.Get("Authorization") != "Bearer token" {
		t.Fatalf("managed identity header = %q, %v", request.Header.Get("Authorization"), err)
	}
	if err := Execute(plan.Backend, &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}); err == nil {
		t.Fatal("managed identity without provider accepted")
	}
	if err := Execute(plan.Backend, &State{}); err == nil {
		t.Fatal("managed identity without request accepted")
	}
	providerErr := errors.New("token unavailable")
	state = &State{Request: httptest.NewRequest(http.MethodGet, "/", nil), AcquireToken: func(string) (string, error) { return "", providerErr }}
	if err := Execute(plan.Backend, state); !errors.Is(err, providerErr) {
		t.Fatalf("provider error = %v", err)
	}
	for _, value := range []string{
		`<policies><backend><authentication-managed-identity resource=""/></backend></policies>`,
		`<policies><backend><authentication-managed-identity resource="@(context.Request.Url)"/></backend></policies>`,
		`<policies><backend><authentication-managed-identity resource="https://backend.test"><unknown/></authentication-managed-identity></backend></policies>`,
	} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid managed identity policy accepted: %s", value)
		}
	}
}

func TestAuthenticationOAuth2Policy(t *testing.T) {
	plan, err := Compile(`<policies><backend><authentication-oauth2 client-id="client" client-secret="secret" token-endpoint="https://login.test/token" resource="api://resource"/></backend></policies>`, true)
	if err != nil || len(plan.Backend) != 1 || plan.Backend[0].Kind != ActionAuthenticationOAuth2 {
		t.Fatalf("oauth2 plan = %+v, %v", plan, err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	state := &State{Request: request, AcquireOAuth2Token: func(clientID, secret, endpoint, resource string) (string, error) {
		if clientID != "client" || secret != "secret" || endpoint != "https://login.test/token" || resource != "api://resource" {
			t.Fatalf("oauth2 inputs = %q %q %q %q", clientID, secret, endpoint, resource)
		}
		return "oauth-token", nil
	}}
	if err := Execute(plan.Backend, state); err != nil || request.Header.Get("Authorization") != "Bearer oauth-token" {
		t.Fatalf("oauth2 header = %q, %v", request.Header.Get("Authorization"), err)
	}
	if err := Execute(plan.Backend, &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}); err == nil {
		t.Fatal("oauth2 without provider accepted")
	}
	if err := Execute(plan.Backend, &State{}); err == nil {
		t.Fatal("oauth2 without request accepted")
	}
	providerErr := errors.New("oauth2 unavailable")
	state = &State{Request: httptest.NewRequest(http.MethodGet, "/", nil), AcquireOAuth2Token: func(string, string, string, string) (string, error) { return "", providerErr }}
	if err := Execute(plan.Backend, state); !errors.Is(err, providerErr) {
		t.Fatalf("oauth2 provider error = %v", err)
	}
	for _, value := range []string{
		`<policies><backend><authentication-oauth2 client-id="" client-secret="secret" token-endpoint="https://login.test/token"/></backend></policies>`,
		`<policies><backend><authentication-oauth2 client-id="client" client-secret="secret" token-endpoint="@(context.Url)"/></backend></policies>`,
		`<policies><backend><authentication-oauth2 client-id="client" client-secret="secret" token-endpoint="https://login.test/token"><unknown/></authentication-oauth2></backend></policies>`,
	} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid oauth2 policy accepted: %s", value)
		}
	}
}

func TestAuthenticationCertificatePolicy(t *testing.T) {
	plan, err := Compile(`<policies><backend><authentication-certificate certificate-id="client-cert"/></backend></policies>`, true)
	if err != nil || len(plan.Backend) != 1 || plan.Backend[0].Kind != ActionAuthenticationCertificate {
		t.Fatalf("certificate auth plan = %+v, %v", plan, err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	attached := ""
	state := &State{Request: request, AttachClientCertificate: func(gotRequest *http.Request, id string) error {
		if gotRequest != request {
			t.Fatal("certificate request changed")
		}
		attached = id
		return nil
	}}
	if err := Execute(plan.Backend, state); err != nil || attached != "client-cert" {
		t.Fatalf("certificate attachment = %q, %v", attached, err)
	}
	if err := Execute(plan.Backend, &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}); err == nil {
		t.Fatal("certificate auth without provider accepted")
	}
	if err := Execute(plan.Backend, &State{}); err == nil {
		t.Fatal("certificate auth without request accepted")
	}
	providerErr := errors.New("certificate unavailable")
	state = &State{Request: httptest.NewRequest(http.MethodGet, "/", nil), AttachClientCertificate: func(*http.Request, string) error { return providerErr }}
	if err := Execute(plan.Backend, state); !errors.Is(err, providerErr) {
		t.Fatalf("certificate provider error = %v", err)
	}
	for _, value := range []string{
		`<policies><backend><authentication-certificate certificate-id=""/></backend></policies>`,
		`<policies><backend><authentication-certificate certificate-id="@(context.Variables['certificate'])"/></backend></policies>`,
		`<policies><backend><authentication-certificate certificate-id="client-cert"><unknown/></authentication-certificate></backend></policies>`,
	} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid certificate auth accepted: %s", value)
		}
	}
}

func TestFindAndReplacePolicy(t *testing.T) {
	plan, err := Compile(`<policies><inbound><find-and-replace from="old" to="new"/></inbound><outbound><find-and-replace from="backend" to="client"/></outbound></policies>`, true)
	if err != nil || len(plan.Inbound) != 1 || len(plan.Outbound) != 1 || plan.Inbound[0].Kind != ActionFindReplace {
		t.Fatalf("find-and-replace plan = %+v, %v", plan, err)
	}
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("old value"))
	state := &State{Request: request}
	if err := Execute(plan.Inbound, state); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil || string(body) != "new value" || request.ContentLength != int64(len("new value")) {
		t.Fatalf("request replacement = %q, %v", body, err)
	}
	replay, err := request.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	replayBody, _ := io.ReadAll(replay)
	if string(replayBody) != "new value" {
		t.Fatalf("request replay = %q", replayBody)
	}
	response := &http.Response{Body: io.NopCloser(strings.NewReader("backend value"))}
	state = &State{Response: response}
	if err := Execute(plan.Outbound, state); err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	if string(body) != "client value" {
		t.Fatalf("response replacement = %q", body)
	}
	if err := Execute(plan.Inbound, &State{}); err == nil {
		t.Fatal("find-and-replace without body accepted")
	}
	badBody := &State{Request: httptest.NewRequest(http.MethodPost, "/", nil)}
	badBody.Request.Body = errorBody{}
	if err := Execute(plan.Inbound, badBody); err == nil {
		t.Fatal("find-and-replace body read error lost")
	}
	for _, value := range []string{
		`<policies><inbound><find-and-replace from="" to="new"/></inbound></policies>`,
		`<policies><inbound><find-and-replace from="old" to="@(context.Request.Body)"/></inbound></policies>`,
		`<policies><inbound><find-and-replace from="old" to="new"><unknown/></find-and-replace></inbound></policies>`,
	} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid find-and-replace accepted: %s", value)
		}
	}
}

func TestJSONToXMLPolicy(t *testing.T) {
	plan, err := Compile(`<policies><outbound><json-to-xml root-element-name="document"/></outbound></policies>`, true)
	if err != nil || len(plan.Outbound) != 1 || plan.Outbound[0].Kind != ActionJSONToXML {
		t.Fatalf("json-to-xml plan = %+v, %v", plan, err)
	}
	response := &http.Response{Body: io.NopCloser(strings.NewReader(`{"name":"Ada","items":[1,"two"],"empty":null}`))}
	state := &State{Response: response}
	if err := Execute(plan.Outbound, state); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || !strings.HasPrefix(string(body), "<document>") || !strings.HasSuffix(string(body), "</document>") || !strings.Contains(string(body), "<name>Ada</name>") || !strings.Contains(string(body), "<items><item>1</item><item>two</item></items>") || !strings.Contains(string(body), "<empty></empty>") {
		t.Fatalf("json-to-xml body = %q, %v", body, err)
	}
	if err := Execute(plan.Outbound, &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}); err == nil {
		t.Fatal("json-to-xml without response accepted")
	}
	bad := &State{Response: &http.Response{Body: io.NopCloser(strings.NewReader("{"))}}
	if err := Execute(plan.Outbound, bad); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	readError := &State{Response: &http.Response{Body: errorBody{}}}
	if err := Execute(plan.Outbound, readError); err == nil {
		t.Fatal("JSON body read error lost")
	}
	if _, err := jsonValueXML("", map[string]any{}); err == nil {
		t.Fatal("empty XML root accepted")
	}
	if _, err := jsonValueXML("root", map[string]any{"": "bad"}); err == nil {
		t.Fatal("empty nested XML element accepted")
	}
	if _, err := jsonValueXML("root", []any{map[string]any{"": "bad"}}); err == nil {
		t.Fatal("empty array XML element accepted")
	}
	if err := Execute([]Action{{Kind: ActionJSONToXML}}, &State{Response: &http.Response{Body: io.NopCloser(strings.NewReader("{}"))}}); err == nil {
		t.Fatal("empty JSON transform root accepted")
	}
	for _, value := range []string{
		`<policies><outbound><json-to-xml root-element-name="@(context.Response.Body)"/></outbound></policies>`,
		`<policies><outbound><json-to-xml><unknown/></json-to-xml></outbound></policies>`,
	} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid json-to-xml accepted: %s", value)
		}
	}
}

type errorBody struct{}

func (errorBody) Read([]byte) (int, error) { return 0, errors.New("body read failed") }
func (errorBody) Close() error             { return nil }

func TestUnsupportedExpressionModes(t *testing.T) {
	xml := `<policies><inbound><set-header name="X"><value>@(context.Request.Method)</value></set-header></inbound><backend/><outbound/><on-error/></policies>`
	plan, err := Compile(xml, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := Execute(plan.Inbound, &State{Request: httptest.NewRequest("GET", "/", nil)}); err == nil {
		t.Fatal("expected runtime error")
	}
	if _, err := Compile(xml, true); err == nil {
		t.Fatal("strict compile should reject expression")
	}
}

func TestCompileValidation(t *testing.T) {
	tests := []struct {
		name string
		xml  string
		want string
	}{
		{"malformed", `<policies>`, "invalid policy XML"},
		{"malformed child", `<policies><inbound><set-header></inbound></policies>`, "invalid policy XML"},
		{"wrong root", `<policy/>`, "root"},
		{"duplicate section", `<policies><inbound/><inbound/></policies>`, "duplicate"},
		{"unknown section", `<policies><wat/></policies>`, "unknown policy section"},
		{"invalid status", `<policies><inbound><return-response><set-status code="nope"/></return-response></inbound></policies>`, "invalid set-status"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Compile(test.xml, false); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Compile() = %v", err)
			}
		})
	}
}

func TestCompileAllP0Actions(t *testing.T) {
	value := `<policies>
	  <inbound>
	    <set-backend-service base-url="https://backend.test/base"/>
	    <rewrite-uri template="/new/path"/>
	    <forward-request/>
	    <unknown-policy/>
	  </inbound>
	  <backend/>
	  <outbound/>
	  <on-error>
	    <return-response>
	      <set-status code="418" reason="Teapot"/>
	      <set-header name="X-Error" exists-action="append"><value>one</value></set-header>
	      <set-body>failed</set-body>
	    </return-response>
	  </on-error>
	</policies>`
	plan, err := Compile(value, false)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	state := &State{Request: request, Headers: make(http.Header)}
	if err := Execute(plan.Inbound[:3], state); err != nil {
		t.Fatal(err)
	}
	if state.BackendURL != "https://backend.test/base" || state.Path != "/new/path" {
		t.Fatalf("state = %+v", state)
	}
	if err := Execute(plan.Inbound[3:], state); err == nil {
		t.Fatal("unknown policy should fail")
	}
	state.Response = &http.Response{Header: make(http.Header)}
	if err := Execute(plan.OnError, state); err != nil {
		t.Fatal(err)
	}
	if !state.Returned || state.StatusCode != 418 || state.Reason != "Teapot" ||
		state.Body != "failed" || state.Headers.Get("X-Error") != "one" {
		t.Fatalf("return response = %+v", state)
	}
}

func TestUnsupportedActionForms(t *testing.T) {
	values := []string{
		`<policies><inbound><set-backend-service/> </inbound></policies>`,
		`<policies><inbound><set-backend-service base-url="https://backend" backend-id="named"/></inbound></policies>`,
		`<policies><inbound><set-backend-service base-url="@(context.Request.Url)"/></inbound></policies>`,
		`<policies><inbound><rewrite-uri template="@(context.Request.Url.Path)"/></inbound></policies>`,
		`<policies><inbound><return-response><set-header name="X"><value>@(1)</value></set-header></return-response></inbound></policies>`,
		`<policies><inbound><return-response><set-body>@{ return "x"; }</set-body></return-response></inbound></policies>`,
		`<policies><inbound><return-response><choose/></return-response></inbound></policies>`,
	}
	for _, value := range values {
		plan, err := Compile(value, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := Execute(plan.Inbound, &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}); err == nil {
			t.Fatalf("expected unsupported runtime error for %s", value)
		}
	}
}

func TestCompileBackendReference(t *testing.T) {
	plan, err := Compile(`<policies><inbound><set-backend-service backend-id="named"/></inbound></policies>`, true)
	if err != nil || len(plan.Inbound) != 1 || plan.Inbound[0].BackendID != "named" {
		t.Fatalf("backend reference = %+v, %v", plan, err)
	}
}

func TestHeaderActionsAndDefaultResponse(t *testing.T) {
	headers := http.Header{"X-Value": {"old"}}
	setHeader(headers, Header{Name: "X-Value", Value: "appended", Action: "append"})
	setHeader(headers, Header{Name: "X-Value", Value: "skipped", Action: "skip"})
	if got := headers.Values("X-Value"); len(got) != 2 {
		t.Fatalf("append/skip = %v", got)
	}
	setHeader(headers, Header{Name: "X-Value", Action: "delete"})
	if headers.Get("X-Value") != "" {
		t.Fatal("delete failed")
	}
	setHeader(headers, Header{Name: "X-Value", Value: "new", Action: "override"})
	if headers.Get("X-Value") != "new" {
		t.Fatal("override failed")
	}
	empty := make(http.Header)
	setHeader(empty, Header{Name: "X-New", Value: "set", Action: "skip"})
	if empty.Get("X-New") != "set" {
		t.Fatal("skip should set absent header")
	}

	state := &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}
	if err := Execute([]Action{{Kind: ActionReturnResponse}}, state); err != nil {
		t.Fatal(err)
	}
	if !state.Returned || state.StatusCode != 0 {
		t.Fatalf("default response state = %+v", state)
	}
}

func TestMissingHeaderValueCompilesLiteral(t *testing.T) {
	plan, err := Compile(`<policies><inbound><set-header name="X"/></inbound></policies>`, false)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := Execute(plan.Inbound, &State{Request: request}); err != nil {
		t.Fatal(err)
	}
	if request.Header.Get("X") != "" {
		t.Fatal("missing value should compile as empty")
	}
}

func TestCompileWithPolicyFragments(t *testing.T) {
	fragments := map[string]string{
		"outer": `<fragment><include-fragment fragment-id="INNER"/><set-header name="X-Outer"><value>outer</value></set-header></fragment>`,
		"inner": `<fragment><set-header name="X-Inner"><value>inner</value></set-header></fragment>`,
	}
	plan, err := CompileWithFragments(`<policies><inbound><include-fragment fragment-id="outer"/></inbound></policies>`, fragments, true)
	if err != nil || len(plan.Inbound) != 2 || plan.Inbound[0].Name != "X-Inner" || plan.Inbound[1].Name != "X-Outer" {
		t.Fatalf("fragment plan = %+v, %v", plan, err)
	}
	if err := ValidateFragment(`<fragment><set-header name="X"><value>v</value></set-header></fragment>`); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"malformed":  `<fragment>`,
		"wrong root": `<policies/>`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateFragment(value); err == nil {
				t.Fatal("invalid fragment was accepted")
			}
		})
	}
	for name, value := range map[string]string{
		"malformed policy":    `<policies>`,
		"missing id":          `<policies><inbound><include-fragment/></inbound></policies>`,
		"missing fragment":    `<policies><inbound><include-fragment fragment-id="missing"/></inbound></policies>`,
		"malformed fragment":  `<policies><inbound><include-fragment fragment-id="bad"/></inbound></policies>`,
		"wrong fragment root": `<policies><inbound><include-fragment fragment-id="wrong"/></inbound></policies>`,
		"cycle":               `<policies><inbound><include-fragment fragment-id="cycle"/></inbound></policies>`,
	} {
		t.Run(name, func(t *testing.T) {
			values := map[string]string{"bad": `<fragment>`, "wrong": `<policies/>`, "cycle": `<fragment><include-fragment fragment-id="cycle"/></fragment>`}
			if _, err := CompileWithFragments(value, values, true); err == nil {
				t.Fatal("invalid fragment policy was accepted")
			}
		})
	}
}
