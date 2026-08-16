package policy

import (
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	expr "github.com/calvinchengx/azure-apim-emulator/internal/expression"
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

func TestLimitConcurrency(t *testing.T) {
	for _, source := range []string{
		`<policies><inbound><limit-concurrency max-count="0"/></inbound></policies>`,
		`<policies><inbound><limit-concurrency max-count="bad"/></inbound></policies>`,
		`<policies><inbound><limit-concurrency max-count="1" key="tenant"><unknown/></limit-concurrency></inbound></policies>`,
	} {
		invalid, invalidErr := Compile(source, false)
		if invalidErr != nil || len(invalid.Inbound) != 1 || invalid.Inbound[0].Kind != ActionUnsupported {
			t.Fatalf("invalid limit-concurrency = %+v, %v", invalid, invalidErr)
		}
	}
	plan, err := Compile(`<policies><inbound><limit-concurrency key="tenant" max-count="1"/></inbound></policies>`, true)
	if err != nil || len(plan.Inbound) != 1 || plan.Inbound[0].Kind != ActionLimitConcurrency {
		t.Fatalf("limit-concurrency plan = %+v, %v", plan, err)
	}
	if err := Execute(plan.Inbound, &State{}); err == nil {
		t.Fatal("limit-concurrency without limiter succeeded")
	}
	requestKey := ""
	requestState := &State{Request: httptest.NewRequest(http.MethodGet, "/", nil), AcquireConcurrency: func(key string, _ int) func() { requestKey = key; return func() {} }}
	if err := Execute([]Action{{Kind: ActionLimitConcurrency, LimitCalls: 1}}, requestState); err != nil || requestKey == "" {
		t.Fatalf("request-key concurrency execution = %+v, %v", requestState, err)
	}
	held := true
	first, second := &State{AcquireConcurrency: func(string, int) func() { return func() { held = false } }}, &State{AcquireConcurrency: func(string, int) func() {
		if held {
			return nil
		}
		return func() {}
	}}
	if err := Execute(plan.Inbound, first); err != nil || first.Returned {
		t.Fatalf("first concurrency execution = %+v, %v", first, err)
	}
	if err := Execute(plan.Inbound, second); err != nil || !second.Returned || second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second concurrency execution = %+v, %v", second, err)
	}
	first.ConcurrencyReleases[0]()
	second = &State{AcquireConcurrency: func(string, int) func() { return func() {} }}
	if err := Execute(plan.Inbound, second); err != nil || second.Returned {
		t.Fatalf("released concurrency execution = %+v, %v", second, err)
	}
	exprPlan, err := Compile(`<policies><inbound><limit-concurrency key="@(context.Request.IpAddress)" max-count="1"/></inbound></policies>`, true)
	if err != nil || len(exprPlan.Inbound) != 1 || exprPlan.Inbound[0].Kind != ActionLimitConcurrency {
		t.Fatalf("limit-concurrency expression plan = %+v, %v", exprPlan, err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.0.0.8:1234"
	exprKey := ""
	if err := Execute(exprPlan.Inbound, &State{Request: request, AcquireConcurrency: func(key string, _ int) func() {
		exprKey = key
		return func() {}
	}}); err != nil || exprKey != "10.0.0.8" {
		t.Fatalf("limit-concurrency expression key = %q, %v", exprKey, err)
	}
	waitPlan, err := Compile(`<policies><inbound><limit-concurrency key="tenant" max-count="1"><wait for="all"><choose><when condition="@(true)"><set-variable name="ran"><value>yes</value></set-variable></when></choose></wait></limit-concurrency></inbound></policies>`, true)
	if err != nil || waitPlan.Inbound[0].Kind != ActionLimitConcurrency || len(waitPlan.Inbound[0].Children) != 1 || waitPlan.Inbound[0].Children[0].Kind != ActionWait {
		t.Fatalf("limit-concurrency wait plan = %+v, %v", waitPlan, err)
	}
	waitState := &State{AcquireConcurrency: func(string, int) func() { return func() {} }}
	if err := Execute(waitPlan.Inbound, waitState); err != nil || waitState.Variables["ran"] != "yes" {
		t.Fatalf("limit-concurrency wait execute = %+v, %v", waitState, err)
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
	if _, err := Compile(`<policies><backend><retry><unknown/></retry></backend></policies>`, true); err == nil {
		t.Fatal("strict mode should reject unsupported retry child")
	}
	nonstrict, err := Compile(`<policies><backend><retry><unknown/></retry></backend></policies>`, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := Execute(nonstrict.Backend, state); err == nil {
		t.Fatal("unsupported retry child should fail during execution")
	}
	waitRetry, err := Compile(`<policies><backend><retry count="0" interval="0"><wait for="all"><choose><when condition="@(true)"><set-backend-service base-url="https://wait.example"/></when></choose></wait></retry></backend></policies>`, true)
	if err != nil || waitRetry.Backend[0].Children[0].Kind != ActionWait {
		t.Fatalf("retry wait plan = %+v, %v", waitRetry, err)
	}
	waitState := &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}
	if err := Execute(waitRetry.Backend, waitState); err != nil || waitState.BackendURL != "https://wait.example" {
		t.Fatalf("retry wait execute = %+v, %v", waitState, err)
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
	exprPlan, err := Compile(`<policies><inbound><set-query-parameter name="n"><value>@(1 + 2)</value></set-query-parameter><set-variable name="flag"><value>@(true)</value></set-variable></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "http://example/", nil)
	state = &State{Request: request}
	if err := Execute(exprPlan.Inbound, state); err != nil || request.URL.Query().Get("n") != "3" || state.Variables["flag"] != "True" {
		t.Fatalf("expression mutation = query %v variables %v, %v", request.URL.Query(), state.Variables, err)
	}
	varPlan, err := Compile(`<policies><inbound><set-variable name="x"><value>@{ var y = 1; return y; }</value></set-variable></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state = &State{Request: httptest.NewRequest(http.MethodGet, "http://example/", nil)}
	if err := Execute(varPlan.Inbound, state); err != nil || state.Variables["x"] != "1" || state.Variables["y"] != "" {
		t.Fatalf("var statement = %+v, %v", state.Variables, err)
	}
	if _, err := Compile(`<policies><inbound><set-variable name="x"><value>@{ if (true) { return 1; } }</value></set-variable></inbound></policies>`, true); err == nil {
		t.Fatal("if without else accepted")
	}
	ifPlan, err := Compile(`<policies><inbound><set-variable name="x"><value>@{ if (true) { return 1; } else { return 2; } }</value></set-variable></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state = &State{Request: httptest.NewRequest(http.MethodGet, "http://example/", nil)}
	if err := Execute(ifPlan.Inbound, state); err != nil || state.Variables["x"] != "1" {
		t.Fatalf("if/else statement = %+v, %v", state.Variables, err)
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
	exprPlan, err := Compile(`<policies><inbound><set-body>@(context.Request.Method)</set-body></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodPut, "/", strings.NewReader("old"))
	state = &State{Request: request}
	if err := Execute(exprPlan.Inbound, state); err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(request.Body)
	if err != nil || string(body) != "PUT" {
		t.Fatalf("expression body = %q, %v", body, err)
	}
	if _, err := Compile(`<policies><inbound><set-body>@(</set-body></inbound></policies>`, true); err == nil {
		t.Fatal("invalid set-body expression accepted")
	}
	unsupportedBody, err := Compile(`<policies><inbound><set-body>@(context.Request.Body.AsJObject())</set-body></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := Execute(unsupportedBody.Inbound, &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}); err == nil {
		t.Fatal("unknown set-body member accepted")
	}
	copied, err := Compile(`<policies><inbound><set-variable name="copy"><value>@(context.Request.Body.AsString())</value></set-variable></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	source := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("payload"))
	copiedState := &State{Request: source}
	if err := Execute(copied.Inbound, copiedState); err != nil || copiedState.Variables["copy"] != "payload" {
		t.Fatalf("body AsString = %+v, %v", copiedState, err)
	}
	replay, err := source.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	replayedBody, _ := io.ReadAll(replay)
	if string(replayedBody) != "payload" {
		t.Fatalf("forwarded body = %q", replayedBody)
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
	literalExpr, err := Compile(`<policies><inbound><check-header name="X"><value>@(1)</value></check-header></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X", "1")
	state = &State{Request: request}
	if err := Execute(literalExpr.Inbound, state); err != nil || state.Returned {
		t.Fatalf("check-header literal expression = %+v, %v", state, err)
	}
	roleExpr, err := Compile(`<policies><inbound><check-header name="@(context.Variables['header'])" failed-check-error-message="@(context.Variables['denied'])"><value>@(context.Variables['role'])</value></check-header></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Role", "admin")
	state = &State{Request: request, Variables: map[string]string{"header": "X-Role", "role": "admin", "denied": "forbidden"}}
	if err := Execute(roleExpr.Inbound, state); err != nil || state.Returned {
		t.Fatalf("check-header variable expression = %+v, %v", state, err)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	state = &State{Request: request, Variables: map[string]string{"header": "X-Role", "role": "admin", "denied": "forbidden"}}
	if err := Execute(roleExpr.Inbound, state); err != nil || !state.Returned || state.Body != "forbidden" {
		t.Fatalf("check-header expression message = %+v, %v", state, err)
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
	constrained, err := Compile(`<policies><inbound><validate-jwt failed-validation-httpcode="401" failed-validation-error-message="claims rejected"><audience>api://demo</audience><issuers><issuer>https://issuer.example</issuer></issuers><required-claims><claim name="role" match="any"><value>admin</value><value>owner</value></claim><claim name="scope" match="all" separator=" "><value>read</value><value>write</value></claim></required-claims></validate-jwt></inbound></policies>`, true)
	if err != nil || len(constrained.Inbound[0].Audiences) != 1 || len(constrained.Inbound[0].Issuers) != 1 || len(constrained.Inbound[0].Claims) != 2 {
		t.Fatalf("jwt constraints = %+v, %v", constrained, err)
	}
	token := testJWT(t, map[string]any{"iss": "https://issuer.example", "aud": []any{"api://demo", "other"}, "role": "admin", "scope": "read write"})
	okReq := httptest.NewRequest(http.MethodGet, "/", nil)
	okReq.Header.Set("Authorization", "Bearer "+token)
	okState := &State{Request: okReq, ValidateToken: func(string) error { return nil }}
	if err := Execute(constrained.Inbound, okState); err != nil || okState.Returned {
		t.Fatalf("matching jwt claims = %+v, %v", okState, err)
	}
	badToken := testJWT(t, map[string]any{"iss": "https://other.example", "aud": "api://demo", "role": "admin", "scope": "read write"})
	badReq := httptest.NewRequest(http.MethodGet, "/", nil)
	badReq.Header.Set("Authorization", "Bearer "+badToken)
	badState := &State{Request: badReq, ValidateToken: func(string) error { return nil }}
	if err := Execute(constrained.Inbound, badState); err != nil || !badState.Returned || badState.StatusCode != http.StatusUnauthorized {
		t.Fatalf("issuer mismatch = %+v, %v", badState, err)
	}
	audMiss := testJWT(t, map[string]any{"iss": "https://issuer.example", "aud": "api://other", "role": "admin", "scope": "read write"})
	audReq := httptest.NewRequest(http.MethodGet, "/", nil)
	audReq.Header.Set("Authorization", "Bearer "+audMiss)
	audState := &State{Request: audReq, ValidateToken: func(string) error { return nil }}
	if err := Execute(constrained.Inbound, audState); err != nil || !audState.Returned {
		t.Fatalf("audience mismatch = %+v, %v", audState, err)
	}
	roleMiss := testJWT(t, map[string]any{"iss": "https://issuer.example", "aud": "api://demo", "role": "guest", "scope": "read write"})
	roleReq := httptest.NewRequest(http.MethodGet, "/", nil)
	roleReq.Header.Set("Authorization", "Bearer "+roleMiss)
	roleState := &State{Request: roleReq, ValidateToken: func(string) error { return nil }}
	if err := Execute(constrained.Inbound, roleState); err != nil || !roleState.Returned {
		t.Fatalf("claim mismatch = %+v, %v", roleState, err)
	}
	wrapped, err := Compile(`<policies><inbound><validate-jwt><audiences><audience>api://demo</audience></audiences></validate-jwt></inbound></policies>`, true)
	if err != nil || len(wrapped.Inbound[0].Audiences) != 1 {
		t.Fatalf("audiences wrapper = %+v, %v", wrapped, err)
	}
	notJWT := httptest.NewRequest(http.MethodGet, "/", nil)
	notJWT.Header.Set("Authorization", "Bearer good")
	notJWTState := &State{Request: notJWT, ValidateToken: func(string) error { return nil }}
	if err := Execute(constrained.Inbound, notJWTState); err != nil || !notJWTState.Returned {
		t.Fatalf("non-jwt with constraints = %+v, %v", notJWTState, err)
	}
	for _, value := range []string{
		`<policies><inbound><validate-jwt><openid-config url="https://issuer.example/.well-known/openid-configuration"/></validate-jwt></inbound></policies>`,
		`<policies><inbound><validate-jwt><client-application-ids><application-id>app</application-id></client-application-ids></validate-jwt></inbound></policies>`,
		`<policies><inbound><validate-jwt><audiences><unknown/></audiences></validate-jwt></inbound></policies>`,
		`<policies><inbound><validate-jwt><issuers><unknown/></issuers></validate-jwt></inbound></policies>`,
		`<policies><inbound><validate-jwt><required-claims><unknown/></required-claims></validate-jwt></inbound></policies>`,
		`<policies><inbound><validate-jwt><required-claims><claim><value>x</value></claim></required-claims></validate-jwt></inbound></policies>`,
		`<policies><inbound><validate-jwt><required-claims><claim name="role" match="maybe"><value>x</value></claim></required-claims></validate-jwt></inbound></policies>`,
		`<policies><inbound><validate-jwt><required-claims><claim name="role"><unknown/></claim></required-claims></validate-jwt></inbound></policies>`,
		`<policies><inbound><validate-jwt><unknown/></validate-jwt></inbound></policies>`,
	} {
		compiled, err := Compile(value, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := Execute(compiled.Inbound, &State{Request: httptest.NewRequest(http.MethodGet, "/", nil), ValidateToken: func(string) error { return nil }}); err == nil {
			t.Fatalf("expected unsupported jwt child for %s", value)
		}
	}
	if _, err := jwtPayload("a.%%%"); err == nil {
		t.Fatal("invalid jwt payload accepted")
	}
	if _, err := jwtPayload("a." + base64.RawURLEncoding.EncodeToString([]byte("not-json"))); err == nil {
		t.Fatal("non-json jwt payload accepted")
	}
	padded := "a." + base64.URLEncoding.EncodeToString([]byte(`{"iss":"padded"}`)) + ".sig"
	if claims, err := jwtPayload(padded); err != nil || claims["iss"] != "padded" {
		t.Fatalf("padded jwt payload = %v %v", claims, err)
	}
	if got := claimStrings(nil, ""); got != nil {
		t.Fatalf("nil claim = %#v", got)
	}
	if got := claimStrings(3.0, ""); len(got) != 1 || got[0] != "3" {
		t.Fatalf("numeric claim = %#v", got)
	}
	if got := claimStrings(true, ""); len(got) != 1 || got[0] != "true" {
		t.Fatalf("bool claim = %#v", got)
	}
	if got := claimStrings(map[string]any{"k": "v"}, ""); len(got) != 1 || !strings.Contains(got[0], "k") {
		t.Fatalf("object claim = %#v", got)
	}
	if got := claimStrings("a, b", ","); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("separated claim = %#v", got)
	}
	if matchClaimValues([]string{"a"}, nil, false) == false || matchClaimValues(nil, nil, true) {
		t.Fatal("empty required claim matching")
	}
}

func testJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
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
	methodPlan, err := Compile(`<policies><inbound><set-method>@(context.Request.Headers.GetValueOrDefault('X-Method', 'patch'))</set-method></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	state = &State{Request: request}
	if err := Execute(methodPlan.Inbound, state); err != nil || request.Method != http.MethodPatch {
		t.Fatalf("set-method expression = %s, %v", request.Method, err)
	}
	corsExpr, err := Compile(`<policies><inbound><cors allowed-origins="@(context.Request.Headers.GetValueOrDefault('Origin'))" allowed-methods="@(context.Variables['methods'])" allowed-headers="@(context.Variables['allow'])" expose-headers="@(context.Variables['expose'])" max-age="@(context.Variables['age'])"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Origin", "https://app.example")
	state = &State{Request: request, Variables: map[string]string{"methods": "GET,POST", "allow": "Authorization", "expose": "X-Request-ID", "age": "600"}}
	if err := Execute(corsExpr.Inbound, state); err != nil {
		t.Fatal(err)
	}
	if state.Headers.Get("Access-Control-Allow-Origin") != "https://app.example" || state.Headers.Get("Access-Control-Allow-Methods") != "GET,POST" || state.Headers.Get("Access-Control-Allow-Headers") != "Authorization" || state.Headers.Get("Access-Control-Expose-Headers") != "X-Request-ID" || state.Headers.Get("Access-Control-Max-Age") != "600" {
		t.Fatalf("cors expression headers = %v", state.Headers)
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
	} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid limit accepted: %s", value)
		}
	}
	exprLimit, err := Compile(`<policies><inbound><quota-by-key calls="1" renewal-period="1" counter-key="@(1)"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	exprKey := ""
	if err := Execute(exprLimit.Inbound, &State{RateLimit: func(key string, _ int, _ time.Duration) bool {
		exprKey = key
		return false
	}}); err != nil || exprKey != "1" {
		t.Fatalf("quota-by-key expression key = %q, %v", exprKey, err)
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

func TestSharedLimitAndResponsePolicies(t *testing.T) {
	rate, err := Compile(`<policies><inbound><rate-limit calls="1" renewal-period="60" retry-after-header-name="X-Retry"/></inbound></policies>`, true)
	if err != nil || len(rate.Inbound) != 1 || rate.Inbound[0].Kind != ActionRateLimit || rate.Inbound[0].Value != "rate-limit" || rate.Inbound[0].StatusCode != http.StatusTooManyRequests || rate.Inbound[0].Body != "X-Retry" {
		t.Fatalf("rate-limit action = %+v, %v", rate, err)
	}
	shared, err := Compile(`<policies><inbound><rate-limit calls="1" renewal-period="60"/></inbound></policies>`, true)
	if err != nil || shared.Inbound[0].Body != "Retry-After" {
		t.Fatalf("default rate-limit header = %+v, %v", shared, err)
	}
	quota, err := Compile(`<policies><inbound><quota calls="1" renewal-period="3600"/></inbound></policies>`, true)
	if err != nil || quota.Inbound[0].Value != "quota" || quota.Inbound[0].StatusCode != http.StatusForbidden || quota.Inbound[0].LimitPeriod != time.Hour {
		t.Fatalf("quota action = %+v, %v", quota, err)
	}
	limited := &State{RateLimit: func(key string, _ int, _ time.Duration) bool { return key == "rate-limit" }}
	if err := Execute(rate.Inbound, limited); err != nil || !limited.Returned || limited.StatusCode != http.StatusTooManyRequests || limited.Headers.Get("X-Retry") != "true" {
		t.Fatalf("rate-limit execute = %+v, %v", limited, err)
	}
	quotaState := &State{RateLimit: func(key string, _ int, _ time.Duration) bool { return key == "quota" }}
	if err := Execute(quota.Inbound, quotaState); err != nil || !quotaState.Returned || quotaState.StatusCode != http.StatusForbidden {
		t.Fatalf("quota execute = %+v, %v", quotaState, err)
	}

	status, err := Compile(`<policies><outbound><set-status code="401" reason="Unauthorized"/></outbound></policies>`, true)
	if err != nil || status.Outbound[0].Kind != ActionSetStatus || status.Outbound[0].StatusCode != http.StatusUnauthorized || status.Outbound[0].Reason != "Unauthorized" {
		t.Fatalf("set-status action = %+v, %v", status, err)
	}
	state := &State{}
	if err := Execute(status.Outbound, state); err != nil || state.Returned || state.StatusCode != http.StatusUnauthorized || state.Reason != "Unauthorized" {
		t.Fatalf("set-status execute = %+v, %v", state, err)
	}

	mocked, err := Compile(`<policies><inbound><mock-response status-code="201" content-type="application/json"/></inbound></policies>`, true)
	if err != nil || mocked.Inbound[0].Kind != ActionReturnResponse || mocked.Inbound[0].StatusCode != http.StatusCreated {
		t.Fatalf("mock-response action = %+v, %v", mocked, err)
	}
	mockState := &State{}
	if err := Execute(mocked.Inbound, mockState); err != nil || !mockState.Returned || mockState.StatusCode != http.StatusCreated || mockState.Headers.Get("Content-Type") != "application/json" || mockState.Body != "" {
		t.Fatalf("mock-response execute = %+v, %v", mockState, err)
	}
	defaults, err := Compile(`<policies><inbound><mock-response/></inbound></policies>`, true)
	if err != nil || defaults.Inbound[0].StatusCode != http.StatusOK || len(defaults.Inbound[0].Headers) != 0 {
		t.Fatalf("default mock-response = %+v, %v", defaults, err)
	}
	statusExpr, err := Compile(`<policies><outbound><set-status code="@(401)" reason="@('Unauthorized')"/></outbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state = &State{}
	if err := Execute(statusExpr.Outbound, state); err != nil || state.StatusCode != http.StatusUnauthorized || state.Reason != "Unauthorized" {
		t.Fatalf("set-status expression = %+v, %v", state, err)
	}
	mockExpr, err := Compile(`<policies><inbound><mock-response status-code="@(201)" content-type="@('application/json')"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	mockState = &State{}
	if err := Execute(mockExpr.Inbound, mockState); err != nil || !mockState.Returned || mockState.StatusCode != http.StatusCreated || mockState.Headers.Get("Content-Type") != "application/json" {
		t.Fatalf("mock-response expression = %+v, %v", mockState, err)
	}
	example, err := Compile(`<policies><inbound><mock-response status-code="200" content-type="application/json"><example>{"ok":true}</example></mock-response></inbound></policies>`, true)
	if err != nil || example.Inbound[0].Body != `{"ok":true}` {
		t.Fatalf("mock-response example plan = %+v, %v", example, err)
	}
	exampleState := &State{}
	if err := Execute(example.Inbound, exampleState); err != nil || !exampleState.Returned || exampleState.Body != `{"ok":true}` {
		t.Fatalf("mock-response example execute = %+v, %v", exampleState, err)
	}
	if _, err := Compile(`<policies><inbound><mock-response><example>@(1 + )</example></mock-response></inbound></policies>`, true); err == nil {
		t.Fatal("invalid mock-response example expression accepted")
	}

	for _, value := range []string{
		`<policies><inbound><rate-limit calls="0" renewal-period="1"/></inbound></policies>`,
		`<policies><inbound><rate-limit calls="bad" renewal-period="1"/></inbound></policies>`,
		`<policies><inbound><rate-limit calls="1" renewal-period="301"/></inbound></policies>`,
		`<policies><inbound><quota calls="1" renewal-period="bad"/></inbound></policies>`,
		`<policies><inbound><quota bandwidth="bad" renewal-period="1"/></inbound></policies>`,
		`<policies><inbound><set-status code="99" reason="bad"/></inbound></policies>`,
		`<policies><inbound><set-status reason="missing"/></inbound></policies>`,
		`<policies><inbound><mock-response status-code="bad"/></inbound></policies>`,
		`<policies><inbound><mock-response status-code="99"/></inbound></policies>`,
	} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid policy accepted: %s", value)
		}
	}
	nested, err := Compile(`<policies><inbound><rate-limit calls="10" renewal-period="60"><api name="demo" calls="1"><operation name="get" calls="1"/></api></rate-limit></inbound></policies>`, true)
	if err != nil || nested.Inbound[0].Kind != ActionRateLimit || len(nested.Inbound[0].Children) != 1 || nested.Inbound[0].Children[0].Value != "rate-limit/api/demo" || nested.Inbound[0].Children[0].Children[0].Value != "rate-limit/api/operation/get" {
		t.Fatalf("nested rate-limit = %+v, %v", nested, err)
	}
	nestedHits := map[string]int{}
	nestedState := &State{RateLimit: func(key string, _ int, _ time.Duration) bool {
		nestedHits[key]++
		return false
	}}
	if err := Execute(nested.Inbound, nestedState); err != nil || nestedHits["rate-limit"] != 1 || nestedHits["rate-limit/api/demo"] != 1 || nestedHits["rate-limit/api/operation/get"] != 1 {
		t.Fatalf("nested rate-limit execute = %v %v", nestedHits, err)
	}
	bandwidth, err := Compile(`<policies><inbound><quota bandwidth="4" renewal-period="60"/></inbound></policies>`, true)
	if err != nil || bandwidth.Inbound[0].LimitBandwidth != 4 || bandwidth.Inbound[0].LimitCalls != 0 {
		t.Fatalf("quota bandwidth plan = %+v, %v", bandwidth, err)
	}
	if err := Execute(bandwidth.Inbound, &State{}); err == nil {
		t.Fatal("quota bandwidth without limiter accepted")
	}
	used := int64(0)
	bwState := &State{Request: httptest.NewRequest(http.MethodPost, "/", strings.NewReader("abcd")), BandwidthLimit: func(key string, add, budget int64, _ time.Duration) bool {
		used += add
		return used > budget
	}}
	if err := Execute(bandwidth.Inbound, bwState); err != nil || bwState.Returned {
		t.Fatalf("first bandwidth = %+v, %v", bwState, err)
	}
	bwState.Returned = false
	if err := Execute(bandwidth.Inbound, bwState); err != nil || !bwState.Returned || bwState.StatusCode != http.StatusForbidden {
		t.Fatalf("limited bandwidth = %+v, %v", bwState, err)
	}
	quotaNested, err := Compile(`<policies><inbound><quota calls="2" renewal-period="60"><api name="demo" calls="1"/></quota></inbound></policies>`, true)
	if err != nil || quotaNested.Inbound[0].Children[0].StatusCode != http.StatusForbidden {
		t.Fatalf("nested quota = %+v, %v", quotaNested, err)
	}
	waitAll, err := Compile(`<policies><inbound><wait for="all"><choose><when condition="@(true)"><set-variable name="a"><value>1</value></set-variable></when></choose><choose><when condition="@(true)"><set-variable name="b"><value>2</value></set-variable></when></choose></wait></inbound></policies>`, true)
	if err != nil || waitAll.Inbound[0].Kind != ActionWait || waitAll.Inbound[0].Action != "all" {
		t.Fatalf("wait all plan = %+v, %v", waitAll, err)
	}
	waitState := &State{}
	if err := Execute(waitAll.Inbound, waitState); err != nil || waitState.Variables["a"] != "1" || waitState.Variables["b"] != "2" {
		t.Fatalf("wait all execute = %+v, %v", waitState, err)
	}
	waitAny, err := Compile(`<policies><inbound><wait for="any"><choose><when condition="@(true)"><set-variable name="picked"><value>first</value></set-variable></when></choose><choose><when condition="@(true)"><set-variable name="picked"><value>second</value></set-variable></when></choose></wait></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	anyState := &State{}
	if err := Execute(waitAny.Inbound, anyState); err != nil || anyState.Variables["picked"] != "first" {
		t.Fatalf("wait any execute = %+v, %v", anyState, err)
	}
	emptyWait, err := Compile(`<policies><inbound><wait for="any"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := Execute(emptyWait.Inbound, &State{}); err != nil {
		t.Fatalf("empty wait any = %v", err)
	}
	anyFail, err := Compile(`<policies><inbound><wait for="any"><choose><when condition="@(1 / 0)"/></choose><choose><when condition="@(true)"><set-variable name="picked"><value>ok</value></set-variable></when></choose></wait></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	failState := &State{}
	if err := Execute(anyFail.Inbound, failState); err != nil || failState.Variables["picked"] != "ok" {
		t.Fatalf("wait any fallback = %+v, %v", failState, err)
	}
	anyLost, err := Compile(`<policies><inbound><wait for="any"><choose><when condition="@(1 / 0)"/></choose></wait></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := Execute(anyLost.Inbound, &State{}); err == nil {
		t.Fatal("wait any lost last error")
	}
	sizeState := &State{Request: httptest.NewRequest(http.MethodPost, "/", strings.NewReader("xyz")), BandwidthLimit: func(_ string, add, _ int64, _ time.Duration) bool {
		return add != 3
	}}
	if err := Execute(bandwidth.Inbound, sizeState); err != nil || sizeState.Returned {
		t.Fatalf("content-length bandwidth = %+v, %v", sizeState, err)
	}
	replay := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("abcd"))
	replay.ContentLength = -1
	replay.GetBody = nil
	if requestSize(&State{Request: replay}) != 4 || replay.GetBody == nil {
		t.Fatal("requestSize did not restore GetBody")
	}
	restored, err := replay.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	restoredBody, _ := io.ReadAll(restored)
	if string(restoredBody) != "abcd" {
		t.Fatalf("restored body = %q", restoredBody)
	}
	if requestSize(&State{}) != 0 {
		t.Fatal("nil request size")
	}
	if requestSize(&State{Request: &http.Request{}}) != 0 {
		t.Fatal("empty request size")
	}
	getBody := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("abcd"))
	getBody.ContentLength = 0
	if requestSize(&State{Request: getBody}) != 4 {
		t.Fatal("GetBody request size")
	}
	failBody := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("abcd"))
	failBody.ContentLength = 0
	failBody.GetBody = func() (io.ReadCloser, error) { return nil, errors.New("get-body") }
	if requestSize(&State{Request: failBody}) != 0 {
		t.Fatal("GetBody error size")
	}
	readFail := &http.Request{Body: errorBody{}}
	if requestSize(&State{Request: readFail}) != 0 {
		t.Fatal("read error size")
	}
	selfWait, err := Compile(`<policies><inbound><wait for="self"/></inbound></policies>`, true)
	if err != nil || selfWait.Inbound[0].Action != "self" {
		t.Fatalf("wait self = %+v, %v", selfWait, err)
	}
	if err := Execute(selfWait.Inbound, &State{}); err != nil {
		t.Fatalf("wait self execute = %v", err)
	}
	waitAllowed, err := Compile(`<policies><inbound><wait><send-request mode="new"><set-url>https://hooks.example</set-url></send-request><cache-lookup-value key="k" variable-name="v"/></wait></inbound></policies>`, true)
	if err != nil || waitAllowed.Inbound[0].Kind != ActionWait || len(waitAllowed.Inbound[0].Children) != 2 {
		t.Fatalf("wait allowed children = %+v, %v", waitAllowed, err)
	}
	if _, err := Compile(`<policies><inbound><wait><choose><when/></choose></wait></inbound></policies>`, true); err == nil {
		t.Fatal("wait compile child accepted")
	}
	if _, err := Compile(`<policies><inbound><limit-concurrency key="k" max-count="1"><wait><choose><when/></choose></wait></limit-concurrency></inbound></policies>`, true); err == nil {
		t.Fatal("limit-concurrency wait compile child accepted")
	}
	if _, err := Compile(`<policies><inbound><rate-limit calls="1" renewal-period="1"><api name="demo" calls="bad"/></rate-limit></inbound></policies>`, true); err == nil {
		t.Fatal("nested invalid calls accepted")
	}
	if _, err := Compile(`<policies><inbound><rate-limit calls="1" renewal-period="1"><api name="demo" calls="1"><operation name="get" calls="bad"/></api></rate-limit></inbound></policies>`, true); err == nil {
		t.Fatal("nested operation invalid calls accepted")
	}
	childErr, err := Compile(`<policies><inbound><quota bandwidth="10" renewal-period="60"><api name="demo" calls="1"/></quota></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := Execute(childErr.Inbound, &State{BandwidthLimit: func(string, int64, int64, time.Duration) bool { return false }}); err == nil {
		t.Fatal("nested calls without rate limiter accepted")
	}
	limitState := &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}
	limitState.Request.RemoteAddr = "10.0.0.8"
	if err := Execute([]Action{{Kind: ActionRateLimit, LimitCalls: 1, LimitPeriod: time.Second, StatusCode: http.StatusTooManyRequests, Body: "Retry-After"}}, &State{Request: limitState.Request, RateLimit: func(key string, _ int, _ time.Duration) bool {
		return key != "10.0.0.8"
	}}); err != nil {
		t.Fatalf("empty key remote addr = %v", err)
	}
	exceeded := &State{RateLimit: func(string, int, time.Duration) bool { return true }}
	if err := Execute([]Action{{Kind: ActionRateLimit, Value: "k", LimitCalls: 1, LimitPeriod: time.Second, StatusCode: http.StatusTooManyRequests, Body: "Retry-After"}}, exceeded); err != nil || exceeded.Headers.Get("Retry-After") != "true" {
		t.Fatalf("limitExceeded headers = %+v, %v", exceeded, err)
	}
	busy, err := Compile(`<policies><inbound><limit-concurrency key="k" max-count="1"><wait><choose><when condition="@(1 / 0)"/></choose></wait></limit-concurrency></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := Execute(busy.Inbound, &State{AcquireConcurrency: func(string, int) func() { return func() {} }}); err == nil {
		t.Fatal("limit-concurrency wait error lost")
	}
	stopped, err := Compile(`<policies><inbound><limit-concurrency key="k" max-count="1"><wait><choose><when condition="@(true)"><return-response><set-status code="204"/></return-response></when></choose></wait></limit-concurrency></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	stopState := &State{AcquireConcurrency: func(string, int) func() { return func() {} }}
	if err := Execute(stopped.Inbound, stopState); err != nil || !stopState.Returned || stopState.StatusCode != http.StatusNoContent {
		t.Fatalf("limit-concurrency returned = %+v, %v", stopState, err)
	}

	for _, value := range []string{
		`<policies><inbound><rate-limit/></inbound></policies>`,
		`<policies><inbound><rate-limit calls="1" renewal-period="1"><unknown/></rate-limit></inbound></policies>`,
		`<policies><inbound><rate-limit calls="1" renewal-period="1"><api calls="1"/></rate-limit></inbound></policies>`,
		`<policies><inbound><rate-limit calls="1" renewal-period="1"><api name="demo" calls="1"><unknown/></api></rate-limit></inbound></policies>`,
		`<policies><inbound><rate-limit calls="1" renewal-period="1"><api name="demo" calls="1"><operation calls="1"/></api></rate-limit></inbound></policies>`,
		`<policies><inbound><rate-limit calls="1" renewal-period="1"><api name="demo" calls="1"><operation name="get" calls="1"><unknown/></operation></api></rate-limit></inbound></policies>`,
		`<policies><inbound><wait for="maybe"/></inbound></policies>`,
		`<policies><inbound><wait><set-header name="X"><value>1</value></set-header></wait></inbound></policies>`,
		`<policies><inbound><limit-concurrency key="k" max-count="1"><set-header name="X"><value>1</value></set-header></limit-concurrency></inbound></policies>`,
		`<policies><inbound><rate-limit calls="1" renewal-period="1"><api name="demo"/></rate-limit></inbound></policies>`,
		`<policies><inbound><set-method/></inbound></policies>`,
		`<policies><inbound><rewrite-uri/></inbound></policies>`,
		`<policies><inbound><set-status code="401" reason="Unauthorized"><unknown/></set-status></inbound></policies>`,
		`<policies><inbound><mock-response><unknown/></mock-response></inbound></policies>`,
		`<policies><inbound><mock-response><schema>{"type":"object"}</schema></mock-response></inbound></policies>`,
	} {
		compiled, err := Compile(value, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := Execute(append(append(append(compiled.Inbound, compiled.Backend...), compiled.Outbound...), compiled.OnError...), &State{}); err == nil {
			t.Fatalf("expected unsupported failure for %s", value)
		}
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
	blockPlan, err := Compile(`<policies><inbound><choose><when condition="@{ return context.Request.Method == 'GET'; }"><set-variable name="picked"><value>block</value></set-variable></when></choose></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state = &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}
	if err := Execute(blockPlan.Inbound, state); err != nil || state.Variables["picked"] != "block" {
		t.Fatalf("block choose = %+v, %v", state, err)
	}
	statusPlan, err := Compile(`<policies><outbound><choose><when condition="@(context.Response.StatusCode >= 500)"><set-header name="X-Retry"><value>@(context.Response.StatusCode.ToString())</value></set-header></when></choose></outbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state = &State{Response: &http.Response{StatusCode: http.StatusBadGateway}, Headers: make(http.Header)}
	if err := Execute(statusPlan.Outbound, state); err != nil || state.Headers.Get("X-Retry") != "502" {
		t.Fatalf("response choose = %+v, %v", state, err)
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
	getPlan, err := Compile(`<policies><inbound><choose><when condition="@(context.Request.Headers.Get('X-Test') == 'yes')"><set-variable name="picked"><value>get</value></set-variable></when></choose></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	getRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	getRequest.Header.Set("X-Test", "yes")
	state = &State{Request: getRequest}
	if err := Execute(getPlan.Inbound, state); err != nil || state.Variables["picked"] != "get" {
		t.Fatalf("headers get choose = %+v, %v", state, err)
	}
	portPlan, err := Compile(`<policies><inbound><choose><when condition="@(context.Request.Url.Port == 443)"><set-variable name="picked"><value>port</value></set-variable></when></choose></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state = &State{Request: httptest.NewRequest(http.MethodGet, "https://api.example/match", nil)}
	if err := Execute(portPlan.Inbound, state); err != nil || state.Variables["picked"] != "port" {
		t.Fatalf("url port choose = %+v, %v", state, err)
	}
	bodyPlan, err := Compile(`<policies><inbound><set-variable name="payload"><value>@(context.Request.Body.AsString())</value></set-variable></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	bodyRequest := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("hello"))
	state = &State{Request: bodyRequest}
	if err := Execute(bodyPlan.Inbound, state); err != nil || state.Variables["payload"] != "hello" {
		t.Fatalf("body as-string = %+v, %v", state, err)
	}
	replayed, err := bodyRequest.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	replayBody, err := io.ReadAll(replayed)
	if err != nil || string(replayBody) != "hello" {
		t.Fatalf("replayed body after AsString = %q %v", replayBody, err)
	}
	lastErrorPlan, err := Compile(`<policies><on-error><choose><when condition="@(context.LastError.Message == 'boom')"><set-variable name="picked"><value>err</value></set-variable></when></choose></on-error></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state = &State{LastError: errors.New("boom")}
	if err := Execute(lastErrorPlan.OnError, state); err != nil || state.Variables["picked"] != "err" {
		t.Fatalf("last-error choose = %+v, %v", state, err)
	}
	if err := Execute([]Action{{Kind: ActionChoose, Branches: []ChooseBranch{{Condition: "@(context.LastError.Reason == 'boom')"}}}}, &State{LastError: errors.New("boom")}); err == nil {
		t.Fatal("unknown last-error member accepted")
	}
	apiPlan, err := Compile(`<policies><inbound><choose><when condition="@(context.Api.Id == 'pets' &amp;&amp; context.Operation.Method == 'GET' &amp;&amp; context.Product == null)"><set-variable name="picked"><value>api</value></set-variable></when></choose></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state = &State{Api: &expr.ApiContext{Id: "pets", Name: "Pets", Path: "pets"}, Operation: &expr.OperationContext{Id: "get", Name: "Get", Method: http.MethodGet, UrlTemplate: "/"}}
	if err := Execute(apiPlan.Inbound, state); err != nil || state.Variables["picked"] != "api" {
		t.Fatalf("deployment context choose = %+v, %v", state, err)
	}
	if err := Execute([]Action{{Kind: ActionChoose, Branches: []ChooseBranch{{Condition: "@(context.Api.Revision == '1')"}}}}, state); err == nil {
		t.Fatal("unknown API member accepted")
	}
	identPlan, err := Compile(`<policies><inbound><set-variable name="who"><value>@(context.User.Name + context.Subscription.Name + context.Deployment.Region)</value></set-variable></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state = &State{User: &expr.NamedContext{Name: "Ada"}, Subscription: &expr.NamedContext{Name: "Dev"}, Deployment: &expr.DeploymentContext{Region: "local"}}
	if err := Execute(identPlan.Inbound, state); err != nil || state.Variables["who"] != "AdaDevlocal" {
		t.Fatalf("identity variables = %+v %v", state, err)
	}
	unsupportedPlan, err := Compile(`<policies><inbound><choose><when condition="@(context.Request.Body.AsJObject() != null)"/></choose></inbound></policies>`, true)
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
	exprPlan, err := Compile(`<policies><backend><authentication-basic username="@(context.Variables['user'])" password="secret"/></backend></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	if err := Execute(exprPlan.Backend, &State{Request: request, Variables: map[string]string{"user": "user"}}); err != nil || request.Header.Get("Authorization") != "Basic dXNlcjpzZWNyZXQ=" {
		t.Fatalf("authentication expression header = %q, %v", request.Header.Get("Authorization"), err)
	}
	for _, value := range []string{
		`<policies><backend><authentication-basic username="" password="secret"/></backend></policies>`,
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
	exprPlan, err := Compile(`<policies><backend><authentication-managed-identity resource="@(context.Request.Url)"/></backend></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "https://backend.test/resource", nil)
	gotResource := ""
	if err := Execute(exprPlan.Backend, &State{Request: request, AcquireToken: func(resource string) (string, error) {
		gotResource = resource
		return "token", nil
	}}); err != nil || gotResource != "https://backend.test/resource" || request.Header.Get("Authorization") != "Bearer token" {
		t.Fatalf("managed identity expression resource = %q header %q, %v", gotResource, request.Header.Get("Authorization"), err)
	}
	for _, value := range []string{
		`<policies><backend><authentication-managed-identity resource=""/></backend></policies>`,
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
	exprPlan, err := Compile(`<policies><backend><authentication-oauth2 client-id="client" client-secret="secret" token-endpoint="@(context.Variables['endpoint'])" resource="api://resource"/></backend></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	gotEndpoint := ""
	if err := Execute(exprPlan.Backend, &State{Request: request, Variables: map[string]string{"endpoint": "https://login.test/token"}, AcquireOAuth2Token: func(clientID, secret, endpoint, resource string) (string, error) {
		if clientID != "client" || secret != "secret" || resource != "api://resource" {
			t.Fatalf("oauth2 expression inputs = %q %q %q %q", clientID, secret, endpoint, resource)
		}
		gotEndpoint = endpoint
		return "oauth-token", nil
	}}); err != nil || gotEndpoint != "https://login.test/token" || request.Header.Get("Authorization") != "Bearer oauth-token" {
		t.Fatalf("oauth2 expression endpoint = %q header %q, %v", gotEndpoint, request.Header.Get("Authorization"), err)
	}
	for _, value := range []string{
		`<policies><backend><authentication-oauth2 client-id="" client-secret="secret" token-endpoint="https://login.test/token"/></backend></policies>`,
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
	exprPlan, err := Compile(`<policies><backend><authentication-certificate certificate-id="@(context.Variables['certificate'])"/></backend></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	attached = ""
	if err := Execute(exprPlan.Backend, &State{Request: request, Variables: map[string]string{"certificate": "client-cert"}, AttachClientCertificate: func(gotRequest *http.Request, id string) error {
		if gotRequest != request {
			t.Fatal("certificate expression request changed")
		}
		attached = id
		return nil
	}}); err != nil || attached != "client-cert" {
		t.Fatalf("certificate expression attachment = %q, %v", attached, err)
	}
	for _, value := range []string{
		`<policies><backend><authentication-certificate certificate-id=""/></backend></policies>`,
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
	expressed, err := Compile(`<policies><outbound><json-to-xml root-element-name="@(context.Variables['root'])"/></outbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	expressedResponse := &http.Response{Body: io.NopCloser(strings.NewReader(`{"name":"Ada"}`))}
	if err := Execute(expressed.Outbound, &State{Response: expressedResponse, Variables: map[string]string{"root": "document"}}); err != nil {
		t.Fatal(err)
	}
	expressedBody, err := io.ReadAll(expressedResponse.Body)
	if err != nil || string(expressedBody) != "<document><name>Ada</name></document>" {
		t.Fatalf("json-to-xml expression body = %q, %v", expressedBody, err)
	}
	for _, value := range []string{
		`<policies><outbound><json-to-xml><unknown/></json-to-xml></outbound></policies>`,
	} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid json-to-xml accepted: %s", value)
		}
	}
}

func TestXMLToJSONPolicy(t *testing.T) {
	plan, err := Compile(`<policies><outbound><xml-to-json/></outbound></policies>`, true)
	if err != nil || len(plan.Outbound) != 1 || plan.Outbound[0].Kind != ActionXMLToJSON {
		t.Fatalf("xml-to-json plan = %+v, %v", plan, err)
	}
	response := &http.Response{Body: io.NopCloser(strings.NewReader(`<root><name>Ada</name><item>one</item><item>two</item><item>three</item><nested><ok>true</ok></nested></root>`))}
	state := &State{Response: response}
	if err := Execute(plan.Outbound, state); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil || document["root"] == nil {
		t.Fatalf("xml-to-json body = %q, %v", body, err)
	}
	root := document["root"].(map[string]any)
	if root["name"] != "Ada" || len(root["item"].([]any)) != 3 || root["nested"].(map[string]any)["ok"] != "true" {
		t.Fatalf("xml-to-json document = %#v", document)
	}
	if err := Execute(plan.Outbound, &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}); err == nil {
		t.Fatal("xml-to-json without response accepted")
	}
	bad := &State{Response: &http.Response{Body: io.NopCloser(strings.NewReader("<root>"))}}
	if err := Execute(plan.Outbound, bad); err == nil {
		t.Fatal("invalid XML accepted")
	}
	readError := &State{Response: &http.Response{Body: errorBody{}}}
	if err := Execute(plan.Outbound, readError); err == nil {
		t.Fatal("XML body read error lost")
	}
	for _, value := range []string{
		`<policies><outbound><xml-to-json><unknown/></xml-to-json></outbound></policies>`,
	} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid xml-to-json accepted: %s", value)
		}
	}
}

func TestJSONPPolicy(t *testing.T) {
	plan, err := Compile(`<policies><outbound><jsonp callback-parameter-name="callback"/></outbound></policies>`, true)
	if err != nil || len(plan.Outbound) != 1 || plan.Outbound[0].Kind != ActionJSONP {
		t.Fatalf("jsonp plan = %+v, %v", plan, err)
	}
	request := httptest.NewRequest(http.MethodGet, "/?callback=handle", nil)
	response := &http.Response{Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}
	state := &State{Request: request, Response: response}
	if err := Execute(plan.Outbound, state); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	if string(body) != "handle({\"ok\":true});" {
		t.Fatalf("jsonp body = %q", body)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	response = &http.Response{Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}
	if err := Execute(plan.Outbound, &State{Request: request, Response: response}); err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	if string(body) != `{"ok":true}` {
		t.Fatalf("jsonp absent callback = %q", body)
	}
	if err := Execute(plan.Outbound, &State{}); err == nil {
		t.Fatal("jsonp without request and response accepted")
	}
	bad := &State{Request: httptest.NewRequest(http.MethodGet, "/?callback=handle", nil), Response: &http.Response{Body: errorBody{}}}
	if err := Execute(plan.Outbound, bad); err == nil {
		t.Fatal("jsonp body read error lost")
	}
	expressed, err := Compile(`<policies><outbound><jsonp callback-parameter-name="@(context.Variables['param'])"/></outbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	expressedRequest := httptest.NewRequest(http.MethodGet, "/?callback=handle", nil)
	expressedResponse := &http.Response{Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}
	if err := Execute(expressed.Outbound, &State{Request: expressedRequest, Response: expressedResponse, Variables: map[string]string{"param": "callback"}}); err != nil {
		t.Fatal(err)
	}
	expressedBody, _ := io.ReadAll(expressedResponse.Body)
	if string(expressedBody) != "handle({\"ok\":true});" {
		t.Fatalf("jsonp expression body = %q", expressedBody)
	}
	for _, value := range []string{
		`<policies><outbound><jsonp callback-parameter-name=""/></outbound></policies>`,
		`<policies><outbound><jsonp callback-parameter-name="callback"><unknown/></jsonp></outbound></policies>`,
	} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid jsonp accepted: %s", value)
		}
	}
}

func TestValueCachePolicies(t *testing.T) {
	plan, err := Compile(`<policies><inbound><cache-lookup-value key="user" variable-name="cached"/></inbound><outbound><cache-store-value key="user" value="Ada" duration="60"/></outbound></policies>`, true)
	if err != nil || len(plan.Inbound) != 1 || len(plan.Outbound) != 1 || plan.Inbound[0].Kind != ActionCacheLookupValue || plan.Outbound[0].Kind != ActionCacheStoreValue {
		t.Fatalf("value cache plan = %+v, %v", plan, err)
	}
	stored := map[string]string{}
	var duration time.Duration
	state := &State{ValueCacheGet: func(key string) (string, bool) { return stored[key], stored[key] != "" }, ValueCacheSet: func(key, value string, got time.Duration) { stored[key], duration = value, got }}
	if err := Execute(plan.Outbound, state); err != nil || stored["user"] != "Ada" || duration != time.Minute {
		t.Fatalf("value cache store = %+v %v, %v", stored, duration, err)
	}
	state = &State{ValueCacheGet: func(key string) (string, bool) { return stored[key], true }}
	if err := Execute(plan.Inbound, state); err != nil || state.Variables["cached"] != "Ada" {
		t.Fatalf("value cache hit = %+v, %v", state, err)
	}
	state = &State{ValueCacheGet: func(string) (string, bool) { return "", false }}
	if err := Execute(plan.Inbound, state); err != nil || state.Variables != nil {
		t.Fatalf("value cache miss = %+v, %v", state, err)
	}
	if err := Execute(plan.Inbound, &State{}); err == nil {
		t.Fatal("value cache lookup without cache accepted")
	}
	if err := Execute(plan.Outbound, &State{}); err == nil {
		t.Fatal("value cache store without cache accepted")
	}
	expressed, err := Compile(`<policies><inbound><cache-lookup-value key="user" variable-name="@(context.Variables['name'])"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state = &State{Variables: map[string]string{"name": "cached"}, ValueCacheGet: func(key string) (string, bool) { return stored[key], stored[key] != "" }}
	if err := Execute(expressed.Inbound, state); err != nil || state.Variables["cached"] != "Ada" {
		t.Fatalf("value cache expression variable = %+v, %v", state.Variables, err)
	}
	emptyName, err := Compile(`<policies><inbound><cache-lookup-value key="user" variable-name="@(context.Variables['name'])"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	emptyState := &State{ValueCacheGet: func(string) (string, bool) { return "Ada", true }}
	if err := Execute(emptyName.Inbound, emptyState); err == nil || emptyState.Variables != nil {
		t.Fatalf("empty evaluated variable-name = %+v, %v", emptyState.Variables, err)
	}
	for _, value := range []string{
		`<policies><inbound><cache-lookup-value key="" variable-name="cached"/></inbound></policies>`,
		`<policies><inbound><cache-lookup-value key="user" variable-name=""/></inbound></policies>`,
		`<policies><inbound><cache-lookup-value key="user" variable-name="cached"><unknown/></cache-lookup-value></inbound></policies>`,
		`<policies><outbound><cache-store-value key="user" value="Ada" duration="bad"/></outbound></policies>`,
		`<policies><outbound><cache-store-value key="user" value="Ada" duration="0"/></outbound></policies>`,
		`<policies><outbound><cache-store-value key="user" value="Ada"><unknown/></cache-store-value></outbound></policies>`,
	} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid value cache accepted: %s", value)
		}
	}
}

func TestValueCacheRemovePolicy(t *testing.T) {
	plan, err := Compile(`<policies><inbound><cache-remove-value key="user"/></inbound></policies>`, true)
	if err != nil || len(plan.Inbound) != 1 || plan.Inbound[0].Kind != ActionCacheRemoveValue {
		t.Fatalf("value cache remove plan = %+v, %v", plan, err)
	}
	removed := ""
	state := &State{ValueCacheRemove: func(key string) { removed = key }}
	if err := Execute(plan.Inbound, state); err != nil || removed != "user" {
		t.Fatalf("value cache remove = %q, %v", removed, err)
	}
	if err := Execute(plan.Inbound, &State{}); err == nil {
		t.Fatal("value cache remove without cache accepted")
	}
	for _, value := range []string{
		`<policies><inbound><cache-remove-value key=""/></inbound></policies>`,
		`<policies><inbound><cache-remove-value key="user"><unknown/></cache-remove-value></inbound></policies>`,
	} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid value cache remove accepted: %s", value)
		}
	}
}

type errorBody struct{}

func (errorBody) Read([]byte) (int, error) { return 0, errors.New("body read failed") }
func (errorBody) Close() error             { return nil }

func TestMutationExpressionModes(t *testing.T) {
	xml := `<policies><inbound><set-header name="X"><value>@(context.Request.Method)</value></set-header></inbound><backend/><outbound/><on-error/></policies>`
	plan, err := Compile(xml, true)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/", nil)
	if err := Execute(plan.Inbound, &State{Request: request}); err != nil || request.Header.Get("X") != "GET" {
		t.Fatalf("set-header expression = %q, %v", request.Header.Get("X"), err)
	}
	if err := Execute(plan.Inbound, &State{}); err == nil {
		t.Fatal("set-header expression without request accepted")
	}
	returned, err := Compile(`<policies><inbound><return-response><set-status code="200"/><set-header name="X"><value>@(1)</value></set-header><set-body>@{ return "x"; }</set-body></return-response></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state := &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}
	if err := Execute(returned.Inbound, state); err != nil || state.Body != "x" || state.Headers.Get("X") != "1" {
		t.Fatalf("return-response expressions = %+v, %v", state, err)
	}
	varHeader, err := Compile(`<policies><inbound><set-header name="X"><value>@{ var y = 1; return y; }</value></set-header></inbound></policies>`, false)
	if err != nil {
		t.Fatal(err)
	}
	headerRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := Execute(varHeader.Inbound, &State{Request: headerRequest}); err != nil || headerRequest.Header.Get("X") != "1" {
		t.Fatalf("set-header var statement = %q, %v", headerRequest.Header.Get("X"), err)
	}
	if _, err := Compile(`<policies><inbound><set-header name="X"><value>@(1 + )</value></set-header></inbound></policies>`, false); err == nil {
		t.Fatal("invalid set-header expression accepted")
	}
	for _, value := range []string{
		`<policies><inbound><set-query-parameter name="x"><value>@(</value></set-query-parameter></inbound></policies>`,
		`<policies><inbound><set-method>@(</set-method></inbound></policies>`,
		`<policies><inbound><return-response><set-header name="X"><value>@(</value></set-header></return-response></inbound></policies>`,
		`<policies><inbound><return-response><set-body>@(</set-body></return-response></inbound></policies>`,
	} {
		if _, err := Compile(value, false); err == nil {
			t.Fatalf("invalid expression accepted: %s", value)
		}
	}
	for _, value := range []string{
		`<policies><inbound><set-query-parameter name="x"><value>@(context.Request.Body.AsJObject())</value></set-query-parameter></inbound></policies>`,
		`<policies><inbound><set-variable name="x"><value>@(context.Request.Body.AsJObject())</value></set-variable></inbound></policies>`,
		`<policies><inbound><set-method>@(context.Request.Body.AsJObject())</set-method></inbound></policies>`,
	} {
		plan, err := Compile(value, true)
		if err != nil {
			t.Fatal(err)
		}
		if err := Execute(plan.Inbound, &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}); err == nil {
			t.Fatalf("unknown member accepted: %s", value)
		}
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
		`<policies><inbound><return-response><set-header name="X"><value>@(context.Request.Body.AsJObject())</value></set-header></return-response></inbound></policies>`,
		`<policies><inbound><return-response><set-body>@(context.Request.Body.AsJObject())</set-body></return-response></inbound></policies>`,
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

func TestDispatchExpressionPolicies(t *testing.T) {
	plan, err := Compile(`<policies><inbound><set-backend-service base-url="@(context.Request.Url)"/><rewrite-uri template="@(context.Request.Url.Path)"/><send-request response-variable-name="probe"><set-url>@(context.Request.Url)</set-url><set-method>@(context.Request.Method)</set-method><set-header name="X-Probe"><value>@(context.Variables['route'])</value></set-header><set-body>@(1)</set-body></send-request></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "https://api.example/items", nil)
	var probed *http.Request
	var probeBody string
	state := &State{Request: request, Variables: map[string]string{"route": "blue"}, SendRequest: func(got *http.Request) (*http.Response, error) {
		probed = got
		body, _ := io.ReadAll(got.Body)
		probeBody = string(body)
		return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(strings.NewReader(""))}, nil
	}}
	if err := Execute(plan.Inbound, state); err != nil {
		t.Fatal(err)
	}
	if state.BackendURL != "https://api.example/items" || state.Path != "/items" || state.Variables["probe"] != "202" {
		t.Fatalf("dispatch state = %+v", state)
	}
	if probed == nil || probed.Method != http.MethodPut || probed.URL.String() != "https://api.example/items" || probed.Header.Get("X-Probe") != "blue" || probeBody != "1" {
		t.Fatalf("probe = %+v body %q", probed, probeBody)
	}

	named, err := Compile(`<policies><inbound><set-backend-service backend-id="@(context.Variables['backend'])"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	namedState := &State{Variables: map[string]string{"backend": "orders"}}
	if err := Execute(named.Inbound, namedState); err != nil || namedState.BackendID != "orders" {
		t.Fatalf("backend-id expression = %+v, %v", namedState, err)
	}

	for _, value := range []string{
		`<policies><inbound><set-backend-service base-url="@(1 + )"/></inbound></policies>`,
		`<policies><inbound><set-backend-service backend-id="@(1 + )"/></inbound></policies>`,
		`<policies><inbound><rewrite-uri template="@(1 + )"/></inbound></policies>`,
		`<policies><inbound><send-request><set-url>@(1 + )</set-url></send-request></inbound></policies>`,
		`<policies><inbound><send-request><set-url>https://probe.example</set-url><set-method>@(1 + )</set-method></send-request></inbound></policies>`,
		`<policies><inbound><send-request><set-url>https://probe.example</set-url><set-header name="X"><value>@(1 + )</value></set-header></send-request></inbound></policies>`,
		`<policies><inbound><send-request><set-url>https://probe.example</set-url><set-body>@(1 + )</set-body></send-request></inbound></policies>`,
		`<policies><inbound><send-one-way-request mode="@(1 + )"><set-url>https://hooks.example</set-url></send-one-way-request></inbound></policies>`,
		`<policies><inbound><send-one-way-request timeout="@(1 + )"><set-url>https://hooks.example</set-url></send-one-way-request></inbound></policies>`,
		`<policies><inbound><send-one-way-request mode="@(new)"><set-url>https://hooks.example</set-url></send-one-way-request></inbound></policies>`,
	} {
		if _, err := Compile(value, false); err == nil {
			t.Fatalf("invalid dispatch expression accepted: %s", value)
		}
	}
	for _, value := range []string{
		`<policies><inbound><set-backend-service base-url="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
		`<policies><inbound><set-backend-service backend-id="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
		`<policies><inbound><rewrite-uri template="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
		`<policies><inbound><send-request><set-url>@(context.Request.Body.AsJObject())</set-url></send-request></inbound></policies>`,
		`<policies><inbound><send-request><set-url>https://probe.example</set-url><set-method>@(context.Request.Body.AsJObject())</set-method></send-request></inbound></policies>`,
		`<policies><inbound><send-request><set-url>https://probe.example</set-url><set-header name="X"><value>@(context.Request.Body.AsJObject())</value></set-header></send-request></inbound></policies>`,
		`<policies><inbound><send-request><set-url>https://probe.example</set-url><set-body>@(context.Request.Body.AsJObject())</set-body></send-request></inbound></policies>`,
		`<policies><inbound><send-one-way-request mode="@(context.Request.Body.AsJObject())"><set-url>https://hooks.example</set-url></send-one-way-request></inbound></policies>`,
		`<policies><inbound><send-one-way-request timeout="@(context.Request.Body.AsJObject())"><set-url>https://hooks.example</set-url></send-one-way-request></inbound></policies>`,
	} {
		compiled, err := Compile(value, true)
		if err != nil {
			t.Fatal(err)
		}
		if err := Execute(compiled.Inbound, &State{Request: httptest.NewRequest(http.MethodGet, "/", nil), SendRequest: func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
		}}); err == nil {
			t.Fatalf("unknown dispatch member accepted: %s", value)
		}
	}
}

func TestCacheAndReplaceExpressionPolicies(t *testing.T) {
	plan, err := Compile(`<policies><inbound><cache-lookup-value key="@(context.Variables['tenant'])" variable-name="cached"/><find-and-replace from="@(context.Variables['from'])" to="@(context.Variables['to'])"/><cache-remove-value key="@(context.Variables['tenant'])"/></inbound><outbound><cache-store-value key="@(context.Variables['tenant'])" value="@(context.Request.Method)" duration="60"/></outbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	stored := map[string]string{}
	var duration time.Duration
	removed := ""
	request := httptest.NewRequest(http.MethodPut, "/", strings.NewReader("old token"))
	state := &State{
		Request:   request,
		Variables: map[string]string{"tenant": "acme", "from": "old", "to": "new"},
		ValueCacheGet: func(key string) (string, bool) {
			return stored[key], stored[key] != ""
		},
		ValueCacheSet:    func(key, value string, got time.Duration) { stored[key], duration = value, got },
		ValueCacheRemove: func(key string) { removed = key },
	}
	if err := Execute(plan.Outbound, state); err != nil || stored["acme"] != http.MethodPut || duration != time.Minute {
		t.Fatalf("store expression = %+v %v, %v", stored, duration, err)
	}
	if err := Execute(plan.Inbound, state); err != nil {
		t.Fatal(err)
	}
	if state.Variables["cached"] != http.MethodPut || removed != "acme" {
		t.Fatalf("lookup/remove expression = %+v removed=%q", state.Variables, removed)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil || string(body) != "new token" {
		t.Fatalf("replace expression = %q, %v", body, err)
	}

	block, err := Compile(`<policies><inbound><cache-lookup-value key="user" variable-name="@{ return context.Variables['name']; }"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	blockState := &State{Variables: map[string]string{"name": "cached"}, ValueCacheGet: func(string) (string, bool) { return "Ada", true }}
	if err := Execute(block.Inbound, blockState); err != nil || blockState.Variables["cached"] != "Ada" {
		t.Fatalf("value cache block variable = %+v, %v", blockState.Variables, err)
	}

	for _, value := range []string{
		`<policies><inbound><find-and-replace from="@(1 + )" to="new"/></inbound></policies>`,
		`<policies><inbound><find-and-replace from="old" to="@(1 + )"/></inbound></policies>`,
		`<policies><inbound><cache-lookup-value key="@(1 + )" variable-name="cached"/></inbound></policies>`,
		`<policies><inbound><cache-lookup-value key="user" variable-name="@(1 + )"/></inbound></policies>`,
		`<policies><outbound><cache-store-value key="@(1 + )" value="Ada"/></outbound></policies>`,
		`<policies><outbound><cache-store-value key="user" value="@(1 + )"/></outbound></policies>`,
		`<policies><inbound><cache-remove-value key="@(1 + )"/></inbound></policies>`,
	} {
		if _, err := Compile(value, false); err == nil {
			t.Fatalf("invalid cache/replace expression accepted: %s", value)
		}
	}
	for _, value := range []string{
		`<policies><inbound><find-and-replace from="@(context.Request.Body.AsJObject())" to="new"/></inbound></policies>`,
		`<policies><inbound><find-and-replace from="old" to="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
		`<policies><inbound><cache-lookup-value key="@(context.Request.Body.AsJObject())" variable-name="cached"/></inbound></policies>`,
		`<policies><inbound><cache-lookup-value key="user" variable-name="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
		`<policies><outbound><cache-store-value key="@(context.Request.Body.AsJObject())" value="Ada"/></outbound></policies>`,
		`<policies><outbound><cache-store-value key="user" value="@(context.Request.Body.AsJObject())"/></outbound></policies>`,
		`<policies><inbound><cache-remove-value key="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
	} {
		compiled, err := Compile(value, true)
		if err != nil {
			t.Fatal(err)
		}
		state := &State{
			Request:          httptest.NewRequest(http.MethodGet, "/", strings.NewReader("old")),
			ValueCacheGet:    func(string) (string, bool) { return "", false },
			ValueCacheSet:    func(string, string, time.Duration) {},
			ValueCacheRemove: func(string) {},
		}
		if err := Execute(append(compiled.Inbound, compiled.Outbound...), state); err == nil {
			t.Fatalf("unknown cache/replace member accepted: %s", value)
		}
	}
}

func TestAccessExpressionPolicies(t *testing.T) {
	for _, value := range []string{
		`<policies><inbound><check-header name="@(1 + )"/></inbound></policies>`,
		`<policies><inbound><check-header name="X"><value>@(1 + )</value></check-header></inbound></policies>`,
		`<policies><inbound><check-header name="X" failed-check-error-message="@(1 + )"/></inbound></policies>`,
		`<policies><inbound><cors allowed-origins="@(1 + )"/></inbound></policies>`,
		`<policies><inbound><cors allowed-methods="@(1 + )"/></inbound></policies>`,
		`<policies><inbound><cors allowed-headers="@(1 + )"/></inbound></policies>`,
		`<policies><inbound><cors expose-headers="@(1 + )"/></inbound></policies>`,
		`<policies><inbound><cors max-age="@(1 + )"/></inbound></policies>`,
		`<policies><inbound><limit-concurrency max-count="1" key="@(1 + )"/></inbound></policies>`,
		`<policies><inbound><rate-limit-by-key calls="1" renewal-period="1" counter-key="@(1 + )"/></inbound></policies>`,
		`<policies><backend><authentication-basic username="@(1 + )" password="secret"/></backend></policies>`,
		`<policies><backend><authentication-basic username="user" password="@(1 + )"/></backend></policies>`,
		`<policies><backend><authentication-managed-identity resource="@(1 + )"/></backend></policies>`,
		`<policies><backend><authentication-oauth2 client-id="@(1 + )" client-secret="secret" token-endpoint="https://login.test/token"/></backend></policies>`,
		`<policies><backend><authentication-oauth2 client-id="client" client-secret="@(1 + )" token-endpoint="https://login.test/token"/></backend></policies>`,
		`<policies><backend><authentication-oauth2 client-id="client" client-secret="secret" token-endpoint="@(1 + )"/></backend></policies>`,
		`<policies><backend><authentication-oauth2 client-id="client" client-secret="secret" token-endpoint="https://login.test/token" resource="@(1 + )"/></backend></policies>`,
		`<policies><backend><authentication-certificate certificate-id="@(1 + )"/></backend></policies>`,
	} {
		if _, err := Compile(value, false); err == nil {
			t.Fatalf("invalid access expression accepted: %s", value)
		}
	}
	for _, value := range []string{
		`<policies><inbound><check-header name="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
		`<policies><inbound><check-header name="X"><value>@(context.Request.Body.AsJObject())</value></check-header></inbound></policies>`,
		`<policies><inbound><check-header name="X" failed-check-error-message="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
		`<policies><inbound><cors allowed-origins="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
		`<policies><inbound><cors allowed-methods="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
		`<policies><inbound><cors allowed-headers="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
		`<policies><inbound><cors expose-headers="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
		`<policies><inbound><cors max-age="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
		`<policies><inbound><limit-concurrency max-count="1" key="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
		`<policies><inbound><rate-limit-by-key calls="1" renewal-period="1" counter-key="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
		`<policies><backend><authentication-basic username="@(context.Request.Body.AsJObject())" password="secret"/></backend></policies>`,
		`<policies><backend><authentication-basic username="user" password="@(context.Request.Body.AsJObject())"/></backend></policies>`,
		`<policies><backend><authentication-managed-identity resource="@(context.Request.Body.AsJObject())"/></backend></policies>`,
		`<policies><backend><authentication-oauth2 client-id="@(context.Request.Body.AsJObject())" client-secret="secret" token-endpoint="https://login.test/token"/></backend></policies>`,
		`<policies><backend><authentication-oauth2 client-id="client" client-secret="@(context.Request.Body.AsJObject())" token-endpoint="https://login.test/token"/></backend></policies>`,
		`<policies><backend><authentication-oauth2 client-id="client" client-secret="secret" token-endpoint="@(context.Request.Body.AsJObject())"/></backend></policies>`,
		`<policies><backend><authentication-oauth2 client-id="client" client-secret="secret" token-endpoint="https://login.test/token" resource="@(context.Request.Body.AsJObject())"/></backend></policies>`,
		`<policies><backend><authentication-certificate certificate-id="@(context.Request.Body.AsJObject())"/></backend></policies>`,
	} {
		compiled, err := Compile(value, true)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, "https://api.example/items", nil)
		request.Header.Set("Origin", "https://app.example")
		state := &State{
			Request: request,
			RateLimit: func(string, int, time.Duration) bool {
				return false
			},
			AcquireConcurrency: func(string, int) func() {
				return func() {}
			},
			AcquireToken:            func(string) (string, error) { return "token", nil },
			AcquireOAuth2Token:      func(string, string, string, string) (string, error) { return "token", nil },
			AttachClientCertificate: func(*http.Request, string) error { return nil },
		}
		if err := Execute(append(compiled.Inbound, compiled.Backend...), state); err == nil {
			t.Fatalf("unknown access member accepted: %s", value)
		}
	}
}

func TestStatusExpressionPolicies(t *testing.T) {
	plan, err := Compile(`<policies><inbound><set-status code="@(context.Variables['code'])" reason="@(context.Variables['reason'])"/><mock-response status-code="@(context.Variables['status'])" content-type="@(context.Variables['type'])"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state := &State{Variables: map[string]string{"code": "401", "reason": "Unauthorized", "status": "201", "type": "application/json"}}
	if err := Execute(plan.Inbound[:1], state); err != nil || state.StatusCode != http.StatusUnauthorized || state.Reason != "Unauthorized" {
		t.Fatalf("set-status variable expression = %+v, %v", state, err)
	}
	state = &State{Variables: map[string]string{"code": "401", "reason": "Unauthorized", "status": "201", "type": "application/json"}}
	if err := Execute(plan.Inbound[1:], state); err != nil || !state.Returned || state.StatusCode != http.StatusCreated || state.Headers.Get("Content-Type") != "application/json" {
		t.Fatalf("mock-response variable expression = %+v, %v", state, err)
	}

	for _, value := range []string{
		`<policies><inbound><set-status code="@(1 + )" reason="Unauthorized"/></inbound></policies>`,
		`<policies><inbound><set-status code="401" reason="@(1 + )"/></inbound></policies>`,
		`<policies><inbound><mock-response status-code="@(1 + )"/></inbound></policies>`,
		`<policies><inbound><mock-response content-type="@(1 + )"/></inbound></policies>`,
	} {
		if _, err := Compile(value, false); err == nil {
			t.Fatalf("invalid status expression accepted: %s", value)
		}
	}
	for _, value := range []string{
		`<policies><inbound><set-status code="@(context.Request.Body.AsJObject())" reason="Unauthorized"/></inbound></policies>`,
		`<policies><inbound><set-status code="401" reason="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
		`<policies><inbound><mock-response status-code="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
		`<policies><inbound><mock-response content-type="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
	} {
		compiled, err := Compile(value, true)
		if err != nil {
			t.Fatal(err)
		}
		if err := Execute(compiled.Inbound, &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}); err == nil {
			t.Fatalf("unknown status member accepted: %s", value)
		}
	}
	for _, value := range []string{
		`<policies><inbound><set-status code="@(99)" reason="bad"/></inbound></policies>`,
		`<policies><inbound><set-status code="@(context.Variables['code'])" reason="bad"/></inbound></policies>`,
		`<policies><inbound><mock-response status-code="@(99)"/></inbound></policies>`,
		`<policies><inbound><mock-response status-code="@(context.Variables['code'])"/></inbound></policies>`,
	} {
		compiled, err := Compile(value, true)
		if err != nil {
			t.Fatal(err)
		}
		if err := Execute(compiled.Inbound, &State{Variables: map[string]string{"code": "bad"}}); err == nil {
			t.Fatalf("invalid evaluated status accepted: %s", value)
		}
	}
}

func TestJSONTransformExpressionPolicies(t *testing.T) {
	for _, value := range []string{
		`<policies><outbound><json-to-xml root-element-name="@(1 + )"/></outbound></policies>`,
		`<policies><outbound><jsonp callback-parameter-name="@(1 + )"/></outbound></policies>`,
	} {
		if _, err := Compile(value, false); err == nil {
			t.Fatalf("invalid json transform expression accepted: %s", value)
		}
	}
	for _, value := range []string{
		`<policies><outbound><json-to-xml root-element-name="@(context.Request.Body.AsJObject())"/></outbound></policies>`,
		`<policies><outbound><jsonp callback-parameter-name="@(context.Request.Body.AsJObject())"/></outbound></policies>`,
	} {
		compiled, err := Compile(value, true)
		if err != nil {
			t.Fatal(err)
		}
		state := &State{
			Request:  httptest.NewRequest(http.MethodGet, "/?callback=handle", nil),
			Response: &http.Response{Body: io.NopCloser(strings.NewReader(`{"ok":true}`))},
		}
		if err := Execute(compiled.Outbound, state); err == nil {
			t.Fatalf("unknown json transform member accepted: %s", value)
		}
	}
}

func TestAzureADTokenExpressionPolicies(t *testing.T) {
	for _, value := range []string{
		`<policies><inbound><validate-azure-ad-token tenant-id="@(1 + )"/></inbound></policies>`,
		`<policies><inbound><validate-azure-ad-token tenant-id="tid" header-name="@(1 + )"/></inbound></policies>`,
		`<policies><inbound><validate-azure-ad-token tenant-id="tid" query-parameter-name="@(1 + )"/></inbound></policies>`,
		`<policies><inbound><validate-azure-ad-token tenant-id="tid" token-value="@(1 + )"/></inbound></policies>`,
		`<policies><inbound><validate-azure-ad-token tenant-id="tid" failed-validation-httpcode="@(1 + )"/></inbound></policies>`,
		`<policies><inbound><validate-azure-ad-token tenant-id="tid" failed-validation-error-message="@(1 + )"/></inbound></policies>`,
	} {
		if _, err := Compile(value, false); err == nil {
			t.Fatalf("invalid entra expression accepted: %s", value)
		}
	}
	for _, value := range []string{
		`<policies><inbound><validate-azure-ad-token tenant-id="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
		`<policies><inbound><validate-azure-ad-token tenant-id="tid" header-name="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
		`<policies><inbound><validate-azure-ad-token tenant-id="tid" query-parameter-name="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
		`<policies><inbound><validate-azure-ad-token tenant-id="tid" failed-validation-httpcode="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
		`<policies><inbound><validate-azure-ad-token tenant-id="tid" failed-validation-error-message="@(context.Request.Body.AsJObject())"/></inbound></policies>`,
	} {
		compiled, err := Compile(value, true)
		if err != nil {
			t.Fatal(err)
		}
		if err := Execute(compiled.Inbound, &State{Request: httptest.NewRequest(http.MethodGet, "/", nil), ValidateToken: func(string) error { return nil }}); err == nil {
			t.Fatalf("unknown entra member accepted: %s", value)
		}
	}
	for _, value := range []string{
		`<policies><inbound><validate-azure-ad-token tenant-id="tid" failed-validation-httpcode="@(99)"/></inbound></policies>`,
		`<policies><inbound><validate-azure-ad-token tenant-id="tid" failed-validation-httpcode="@(context.Variables['code'])"/></inbound></policies>`,
	} {
		compiled, err := Compile(value, true)
		if err != nil {
			t.Fatal(err)
		}
		if err := Execute(compiled.Inbound, &State{Request: httptest.NewRequest(http.MethodGet, "/", nil), Variables: map[string]string{"code": "bad"}, ValidateToken: func(string) error { return nil }}); err == nil {
			t.Fatalf("invalid evaluated entra status accepted: %s", value)
		}
	}
	emptyTenant, err := Compile(`<policies><inbound><validate-azure-ad-token tenant-id="@(context.Variables['tenant'])"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := Execute(emptyTenant.Inbound, &State{Request: httptest.NewRequest(http.MethodGet, "/", nil), ValidateToken: func(string) error { return nil }}); err == nil {
		t.Fatal("empty evaluated tenant-id accepted")
	}
	block, err := Compile(`<policies><inbound><validate-azure-ad-token tenant-id="@{ return context.Variables['tenant']; }" header-name="@{ return context.Variables['header']; }"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Token", "Bearer good")
	state := &State{Request: request, Variables: map[string]string{"tenant": "organizations", "header": "X-Token"}, ValidateToken: func(token string) error {
		if token != "good" {
			return errors.New("bad token")
		}
		return nil
	}}
	if err := Execute(block.Inbound, state); err != nil || state.Returned {
		t.Fatalf("block entra expression = %+v, %v", state, err)
	}
	code, err := Compile(`<policies><inbound><validate-azure-ad-token tenant-id="tid" failed-validation-httpcode="@(403)" failed-validation-error-message="@(context.Variables['msg'])"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	rejected := &State{Request: httptest.NewRequest(http.MethodGet, "/", nil), Variables: map[string]string{"msg": "aad rejected"}, ValidateToken: func(string) error { return errors.New("bad token") }}
	if err := Execute(code.Inbound, rejected); err != nil || !rejected.Returned || rejected.StatusCode != http.StatusForbidden || rejected.Body != "aad rejected" {
		t.Fatalf("literal entra status expression = %+v, %v", rejected, err)
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

func TestIntegrationPolicies(t *testing.T) {
	oneWay, err := Compile(`<policies><inbound><send-one-way-request mode="new" timeout="20"><set-url>https://hooks.example/slack</set-url><set-method>POST</set-method><set-header name="X-Hook"><value>yes</value></set-header><set-body>alert</set-body></send-one-way-request></inbound></policies>`, true)
	if err != nil || oneWay.Inbound[0].Kind != ActionSendOneWay || oneWay.Inbound[0].ResponseVar != "" || oneWay.Inbound[0].Name != "new" || oneWay.Inbound[0].MaxAge != "20" {
		t.Fatalf("send-one-way-request action = %+v, %v", oneWay, err)
	}
	sent := 0
	state := &State{SendRequest: func(request *http.Request) (*http.Response, error) {
		sent++
		if request.Method != http.MethodPost || request.URL.String() != "https://hooks.example/slack" || request.Header.Get("X-Hook") != "yes" {
			t.Fatalf("one-way request = %+v", request)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ignored"))}, errors.New("transport failed")
	}}
	if err := Execute(oneWay.Inbound, state); err != nil || state.Returned || sent != 1 {
		t.Fatalf("one-way execute = %+v, %v sent=%d", state, err, sent)
	}
	if err := Execute(oneWay.Inbound, &State{}); err == nil {
		t.Fatal("send-one-way-request without transport accepted")
	}
	if err := Execute(oneWay.Inbound, &State{SendRequest: func(*http.Request) (*http.Response, error) { return nil, nil }}); err != nil {
		t.Fatalf("nil one-way response = %v", err)
	}
	invalidURL, err := Compile(`<policies><inbound><send-one-way-request><set-url>://bad</set-url></send-one-way-request></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := Execute(invalidURL.Inbound, &State{SendRequest: func(*http.Request) (*http.Response, error) { return nil, nil }}); err == nil {
		t.Fatal("invalid one-way URL accepted")
	}
	// timeout="@(20)" compiles and evaluates to "20"; the transport hook has no deadline, so the value is discarded after eval.
	oneWayExpr, err := Compile(`<policies><inbound><send-one-way-request mode="@(context.Variables['mode'])" timeout="@(20)"><set-url>https://hooks.example/slack</set-url></send-one-way-request></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	sentExpr := 0
	exprOneWay := &State{Variables: map[string]string{"mode": "new"}, SendRequest: func(*http.Request) (*http.Response, error) {
		sentExpr++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ignored"))}, nil
	}}
	if err := Execute(oneWayExpr.Inbound, exprOneWay); err != nil || sentExpr != 1 {
		t.Fatalf("expressed one-way = sent=%d, %v", sentExpr, err)
	}
	block, err := Compile(`<policies><inbound><send-one-way-request mode="@{ return context.Variables['mode']; }" timeout="@{ return 20; }"><set-url>https://hooks.example/slack</set-url></send-one-way-request></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	sentBlock := 0
	if err := Execute(block.Inbound, &State{Variables: map[string]string{"mode": "new"}, SendRequest: func(*http.Request) (*http.Response, error) {
		sentBlock++
		return nil, nil
	}}); err != nil || sentBlock != 1 {
		t.Fatalf("block one-way = sent=%d, %v", sentBlock, err)
	}
	copyMode, err := Compile(`<policies><inbound><send-one-way-request mode="@(context.Variables['mode'])"><set-url>https://hooks.example/slack</set-url></send-one-way-request></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := Execute(copyMode.Inbound, &State{Variables: map[string]string{"mode": "copy"}, SendRequest: func(*http.Request) (*http.Response, error) { return nil, nil }}); err == nil {
		t.Fatal("expressed copy mode accepted")
	}

	entra, err := Compile(`<policies><inbound><validate-azure-ad-token tenant-id="organizations" header-name="X-Token" failed-validation-httpcode="403" failed-validation-error-message="aad rejected"/></inbound></policies>`, true)
	if err != nil || entra.Inbound[0].Kind != ActionValidateJWT || entra.Inbound[0].Name != "X-Token" {
		t.Fatalf("validate-azure-ad-token action = %+v, %v", entra, err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Token", "Bearer good")
	aad := &State{Request: request, ValidateToken: func(token string) error {
		if token != "good" {
			return errors.New("bad token")
		}
		return nil
	}}
	if err := Execute(entra.Inbound, aad); err != nil || aad.Returned {
		t.Fatalf("valid entra token = %+v, %v", aad, err)
	}
	query, err := Compile(`<policies><inbound><validate-azure-ad-token tenant-id="organizations" query-parameter-name="access_token"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	queryReq := httptest.NewRequest(http.MethodGet, "/?access_token=good", nil)
	queryState := &State{Request: queryReq, ValidateToken: func(token string) error {
		if token != "good" {
			return errors.New("bad token")
		}
		return nil
	}}
	if err := Execute(query.Inbound, queryState); err != nil || queryState.Returned {
		t.Fatalf("query token = %+v, %v", queryState, err)
	}
	if tokenFromRequest(&http.Request{}, Action{Variable: "access_token"}) != "" {
		t.Fatal("nil URL should yield an empty token")
	}
	expressed, err := Compile(`<policies><inbound><validate-azure-ad-token tenant-id="@(context.Variables['tenant'])" header-name="@(context.Variables['header'])" query-parameter-name="@(context.Variables['query'])" failed-validation-httpcode="@(context.Variables['code'])" failed-validation-error-message="@(context.Variables['msg'])"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	exprReq := httptest.NewRequest(http.MethodGet, "/?access_token=good", nil)
	exprReq.Header.Set("X-Token", "Bearer ignored")
	exprState := &State{Request: exprReq, Variables: map[string]string{"tenant": "organizations", "header": "X-Token", "query": "access_token", "code": "403", "msg": "aad rejected"}, ValidateToken: func(token string) error {
		if token != "good" {
			return errors.New("bad token")
		}
		return nil
	}}
	if err := Execute(expressed.Inbound, exprState); err != nil || exprState.Returned {
		t.Fatalf("expressed entra token = %+v, %v", exprState, err)
	}
	exprReq.Header.Del("X-Token")
	exprReq.URL.RawQuery = ""
	exprState = &State{Request: exprReq, Variables: map[string]string{"tenant": "organizations", "header": "X-Token", "query": "access_token", "code": "403", "msg": "aad rejected"}, ValidateToken: func(string) error { return errors.New("bad token") }}
	if err := Execute(expressed.Inbound, exprState); err != nil || !exprState.Returned || exprState.StatusCode != http.StatusForbidden || exprState.Body != "aad rejected" {
		t.Fatalf("expressed entra rejection = %+v, %v", exprState, err)
	}
	apps, err := Compile(`<policies><inbound><validate-azure-ad-token tenant-id="organizations"><client-application-ids><application-id>app-1</application-id></client-application-ids><required-claims><claim name="roles" match="all"><value>reader</value></claim></required-claims></validate-azure-ad-token></inbound></policies>`, true)
	if err != nil || len(apps.Inbound[0].ClientAppIDs) != 1 || len(apps.Inbound[0].Claims) != 1 {
		t.Fatalf("entra constraints = %+v, %v", apps, err)
	}
	appToken := testJWT(t, map[string]any{"azp": "app-1", "roles": []any{"reader", "writer"}})
	appReq := httptest.NewRequest(http.MethodGet, "/", nil)
	appReq.Header.Set("Authorization", "Bearer "+appToken)
	appState := &State{Request: appReq, ValidateToken: func(string) error { return nil }}
	if err := Execute(apps.Inbound, appState); err != nil || appState.Returned {
		t.Fatalf("matching entra claims = %+v, %v", appState, err)
	}
	wrongApp := testJWT(t, map[string]any{"appid": "other", "roles": []any{"reader"}})
	wrongReq := httptest.NewRequest(http.MethodGet, "/", nil)
	wrongReq.Header.Set("Authorization", "Bearer "+wrongApp)
	wrongState := &State{Request: wrongReq, ValidateToken: func(string) error { return nil }}
	if err := Execute(apps.Inbound, wrongState); err != nil || !wrongState.Returned {
		t.Fatalf("entra app mismatch = %+v, %v", wrongState, err)
	}
	missingRole := testJWT(t, map[string]any{"azp": "app-1", "roles": []any{"writer"}})
	missingReq := httptest.NewRequest(http.MethodGet, "/", nil)
	missingReq.Header.Set("Authorization", "Bearer "+missingRole)
	missingState := &State{Request: missingReq, ValidateToken: func(string) error { return nil }}
	if err := Execute(apps.Inbound, missingState); err != nil || !missingState.Returned {
		t.Fatalf("entra claim mismatch = %+v, %v", missingState, err)
	}
	emptyKids, err := Compile(`<policies><inbound><validate-jwt><audience></audience><issuer></issuer></validate-jwt></inbound></policies>`, true)
	if err != nil || len(emptyKids.Inbound[0].Audiences) != 0 || len(emptyKids.Inbound[0].Issuers) != 0 {
		t.Fatalf("empty jwt children = %+v, %v", emptyKids, err)
	}

	cross, err := Compile(`<policies><inbound><cross-domain><cross-domain-policy><allow-http-request-headers-from domain="*" headers="*"/><site-control permitted-cross-domain-policies="all">note</site-control></cross-domain-policy></cross-domain></inbound></policies>`, true)
	if err != nil || cross.Inbound[0].Kind != ActionReturnResponse || !strings.Contains(cross.Inbound[0].Body, `domain="*"`) || !strings.Contains(cross.Inbound[0].Body, ">note</site-control>") {
		t.Fatalf("cross-domain action = %+v, %v", cross, err)
	}
	crossState := &State{}
	if err := Execute(cross.Inbound, crossState); err != nil || !crossState.Returned || crossState.Headers.Get("Content-Type") != "text/x-cross-domain-policy" {
		t.Fatalf("cross-domain execute = %+v, %v", crossState, err)
	}

	redirect, err := Compile(`<policies><inbound><redirect-content-urls/></inbound><outbound><redirect-content-urls/></outbound></policies>`, true)
	if err != nil || redirect.Inbound[0].Kind != ActionRedirectContentURLs {
		t.Fatalf("redirect-content-urls action = %+v, %v", redirect, err)
	}
	inboundReq := httptest.NewRequest(http.MethodPost, "https://gateway.example/api", strings.NewReader(`{"url":"https://gateway.example/items"}`))
	inbound := &State{Request: inboundReq, BackendURL: "https://backend.example/"}
	if err := Execute(redirect.Inbound, inbound); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(inbound.Request.Body)
	if string(body) != `{"url":"https://backend.example/items"}` {
		t.Fatalf("inbound rewrite = %s", body)
	}
	replayed, err := inbound.Request.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	replayedBody, _ := io.ReadAll(replayed)
	if string(replayedBody) != `{"url":"https://backend.example/items"}` {
		t.Fatalf("inbound rewrite GetBody = %s", replayedBody)
	}
	outboundReq := httptest.NewRequest(http.MethodGet, "https://gateway.example/api", nil)
	outbound := &State{Request: outboundReq, BackendURL: "https://backend.example", Response: &http.Response{Body: io.NopCloser(strings.NewReader(`{"url":"https://backend.example/items"}`))}}
	if err := Execute(redirect.Outbound, outbound); err != nil {
		t.Fatal(err)
	}
	outBody, _ := io.ReadAll(outbound.Response.Body)
	if string(outBody) != `{"url":"https://gateway.example/items"}` {
		t.Fatalf("outbound rewrite = %s", outBody)
	}
	tlsReq := httptest.NewRequest(http.MethodGet, "/api", nil)
	tlsReq.Host = "secure.example"
	tlsReq.TLS = &tls.ConnectionState{}
	if requestBaseURL(tlsReq) != "https://secure.example" {
		t.Fatalf("tls base URL = %s", requestBaseURL(tlsReq))
	}
	hostReq := httptest.NewRequest(http.MethodGet, "http://from-url.example/api", nil)
	hostReq.Host = ""
	if requestBaseURL(hostReq) != "http://from-url.example" {
		t.Fatalf("url host base = %s", requestBaseURL(hostReq))
	}
	if err := Execute(redirect.Inbound, &State{}); err == nil {
		t.Fatal("redirect-content-urls without request accepted")
	}
	if err := Execute(redirect.Inbound, &State{Request: httptest.NewRequest(http.MethodGet, "https://gateway.example/", nil)}); err == nil {
		t.Fatal("redirect-content-urls without backend accepted")
	}
	emptyBody := httptest.NewRequest(http.MethodGet, "https://gateway.example/", nil)
	emptyBody.Body = nil
	if err := Execute(redirect.Inbound, &State{Request: emptyBody, BackendURL: "https://backend.example"}); err == nil {
		t.Fatal("redirect-content-urls without body accepted")
	}
	broken := httptest.NewRequest(http.MethodGet, "https://gateway.example/", nil)
	broken.Body = errorBody{}
	if err := Execute(redirect.Inbound, &State{Request: broken, BackendURL: "https://backend.example"}); err == nil {
		t.Fatal("redirect-content-urls body read error lost")
	}

	for _, value := range []string{
		`<policies><inbound><validate-azure-ad-token tenant-id="tid" failed-validation-httpcode="bad"/></inbound></policies>`,
	} {
		if _, err := Compile(value, true); err == nil {
			t.Fatalf("invalid policy accepted: %s", value)
		}
	}
	for _, value := range []string{
		`<policies><inbound><send-one-way-request mode="copy"><set-url>https://hooks.example</set-url></send-one-way-request></inbound></policies>`,
		`<policies><inbound><send-one-way-request/></inbound></policies>`,
		`<policies><inbound><send-one-way-request><set-url>https://hooks.example</set-url><authentication-certificate thumbprint="abc"/></send-one-way-request></inbound></policies>`,
		`<policies><inbound><validate-azure-ad-token/></inbound></policies>`,
		`<policies><inbound><validate-azure-ad-token tenant-id="tid" token-value="@(token)"/></inbound></policies>`,
		`<policies><inbound><validate-azure-ad-token tenant-id="tid" token-value="raw"/></inbound></policies>`,
		`<policies><inbound><validate-azure-ad-token tenant-id="tid"><client-application-ids><unknown/></client-application-ids></validate-azure-ad-token></inbound></policies>`,
		`<policies><inbound><validate-azure-ad-token tenant-id="tid"><unknown/></validate-azure-ad-token></inbound></policies>`,
		`<policies><inbound><redirect-content-urls><unknown/></redirect-content-urls></inbound></policies>`,
	} {
		compiled, err := Compile(value, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := Execute(append(append(compiled.Inbound, compiled.Outbound...), compiled.OnError...), &State{Request: httptest.NewRequest(http.MethodGet, "/", nil), ValidateToken: func(string) error { return nil }, SendRequest: func(*http.Request) (*http.Response, error) { return nil, nil }}); err == nil {
			t.Fatalf("expected unsupported failure for %s", value)
		}
	}
}
