package policy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	expr "github.com/calvinchengx/azure-apim-emulator/internal/expression"
)

// tokenCounter is a scripted stand-in for the gateway's sliding window, so the
// policy's behaviour can be tested apart from the window's arithmetic.
type tokenCounter struct {
	remaining, retryAfter int
	allowed               bool
	keys                  []string
	estimates             []int
}

func (c *tokenCounter) limit(key string, _ int, estimate int) (int, int, bool) {
	c.keys = append(c.keys, key)
	c.estimates = append(c.estimates, estimate)
	return c.remaining, c.retryAfter, c.allowed
}

func llmState(counter *tokenCounter, body string) *State {
	request, _ := http.NewRequest(http.MethodPost, "https://gateway.test/openai/deployments/gpt/chat/completions", strings.NewReader(body))
	request.RemoteAddr = "10.0.0.8:52344"
	return &State{
		Request: request, Headers: make(http.Header), Variables: map[string]string{},
		TokenLimit: counter.limit,
		Api:        &expr.ApiContext{Id: "openai-api", Name: "OpenAI", Path: "openai"},
	}
}

func TestLLMTokenLimitAllowsAndReports(t *testing.T) {
	plan, err := Compile(`<policies><inbound><llm-token-limit counter-key="@(context.Request.IpAddress)" tokens-per-minute="500" remaining-tokens-header-name="x-remaining" remaining-tokens-variable-name="left"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	counter := &tokenCounter{remaining: 420, allowed: true}
	state := llmState(counter, `{"messages":[{"role":"user","content":"hello"}]}`)
	if err := Execute(plan.Inbound, state); err != nil {
		t.Fatal(err)
	}
	if state.Returned {
		t.Fatal("an allowed request was refused")
	}
	if state.Headers.Get("x-remaining") != "420" || state.Variables["left"] != "420" {
		t.Fatalf("remaining not reported: %v %v", state.Headers, state.Variables)
	}
	// With estimate-prompt-tokens absent, nothing is charged up front: every
	// number comes from the provider afterwards.
	if len(counter.estimates) != 1 || counter.estimates[0] != 0 {
		t.Fatalf("estimates = %v", counter.estimates)
	}
	if state.LLM == nil || state.LLM.TokensPerMinute != 500 {
		t.Fatalf("governance not left for the gateway: %#v", state.LLM)
	}
}

func TestLLMTokenLimitRefusesWhenSpent(t *testing.T) {
	plan, err := Compile(`<policies><inbound><llm-token-limit counter-key="tenant" tokens-per-minute="100" retry-after-header-name="x-wait" retry-after-variable-name="wait"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	counter := &tokenCounter{retryAfter: 37, allowed: false}
	state := llmState(counter, `{}`)
	if err := Execute(plan.Inbound, state); err != nil {
		t.Fatal(err)
	}
	if !state.Returned || state.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("refusal = %v %d", state.Returned, state.StatusCode)
	}
	if state.Headers.Get("x-wait") != "37" || state.Variables["wait"] != "37" {
		t.Fatalf("retry-after not reported: %v", state.Headers)
	}
	// The standard header goes out whether or not the policy named a custom
	// one: a 429 without it tells the client to guess.
	if state.Headers.Get("Retry-After") != "37" {
		t.Fatalf("standard Retry-After missing: %v", state.Headers)
	}
}

// An estimate is charged before the model answers, and reading the body to
// produce it must leave the body intact for the backend.
func TestLLMTokenLimitEstimatePreservesTheBody(t *testing.T) {
	plan, err := Compile(`<policies><inbound><llm-token-limit counter-key="tenant" tokens-per-minute="100" estimate-prompt-tokens="true"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	counter := &tokenCounter{remaining: 90, allowed: true}
	body := `{"messages":[{"role":"user","content":"the quick brown fox"}]}`
	state := llmState(counter, body)
	if err := Execute(plan.Inbound, state); err != nil {
		t.Fatal(err)
	}
	if len(counter.estimates) != 1 || counter.estimates[0] <= 0 {
		t.Fatalf("no estimate was charged: %v", counter.estimates)
	}
	forwarded := make([]byte, len(body))
	read, _ := state.Request.Body.Read(forwarded)
	if string(forwarded[:read]) != body {
		t.Fatalf("the prompt was consumed by estimation: %q", string(forwarded[:read]))
	}
	if state.Request.ContentLength != int64(len(body)) {
		t.Fatalf("content length = %d", state.Request.ContentLength)
	}
}

func TestLLMEmitTokenMetricRecordsDimensions(t *testing.T) {
	plan, err := Compile(`<policies><inbound><llm-emit-token-metric namespace="contoso"><dimension name="API ID" value="@(context.Api.Id)"/><dimension name="Client"/></llm-emit-token-metric></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	counter := &tokenCounter{allowed: true}
	state := llmState(counter, `{}`)
	if err := Execute(plan.Inbound, state); err != nil {
		t.Fatal(err)
	}
	if state.LLM == nil || !state.LLM.Emit || state.LLM.Namespace != "contoso" {
		t.Fatalf("metric intent not recorded: %#v", state.LLM)
	}
	// A dimension with no value defaults to its own name, which is what Azure
	// does and what makes `<dimension name="Client"/>` meaningful.
	if state.LLM.Dimensions["API ID"] != "openai-api" {
		t.Fatalf("expression dimension = %v", state.LLM.Dimensions)
	}
	if state.LLM.Dimensions["Client"] != "Client" {
		t.Fatalf("dimensions = %v", state.LLM.Dimensions)
	}
}

// The two nodes compose in either order, because a policy author may write
// them in either order and both leave state on the same governance record.
func TestLLMNodesComposeInEitherOrder(t *testing.T) {
	for _, source := range []string{
		`<policies><inbound><llm-token-limit counter-key="k" tokens-per-minute="10"/><llm-emit-token-metric namespace="n"><dimension name="d"/></llm-emit-token-metric></inbound></policies>`,
		`<policies><inbound><llm-emit-token-metric namespace="n"><dimension name="d"/></llm-emit-token-metric><llm-token-limit counter-key="k" tokens-per-minute="10"/></inbound></policies>`,
	} {
		plan, err := Compile(source, true)
		if err != nil {
			t.Fatal(err)
		}
		counter := &tokenCounter{remaining: 5, allowed: true}
		state := llmState(counter, `{}`)
		if err := Execute(plan.Inbound, state); err != nil {
			t.Fatal(err)
		}
		if state.LLM == nil || !state.LLM.Emit || state.LLM.CounterKey != "k" || state.LLM.TokensPerMinute != 10 {
			t.Fatalf("composition lost state for %s: %#v", source, state.LLM)
		}
	}
}

// Azure ships the same policy under a provider-specific name and a generic one.
// A configuration written against either must work here.
func TestAzureOpenAIAliasesCompileIdentically(t *testing.T) {
	for _, name := range []string{"azure-openai-token-limit", "llm-token-limit"} {
		plan, err := Compile(`<policies><inbound><`+name+` counter-key="k" tokens-per-minute="10"/></inbound></policies>`, true)
		if err != nil || len(plan.Inbound) != 1 || plan.Inbound[0].Kind != ActionLLMTokenLimit {
			t.Fatalf("%s did not compile to a token limit: %v", name, err)
		}
	}
	for _, name := range []string{"azure-openai-emit-token-metric", "llm-emit-token-metric"} {
		plan, err := Compile(`<policies><inbound><`+name+` namespace="n"><dimension name="d"/></`+name+`></inbound></policies>`, true)
		if err != nil || len(plan.Inbound) != 1 || plan.Inbound[0].Kind != ActionLLMEmitTokenMetric {
			t.Fatalf("%s did not compile to an emit-token-metric: %v", name, err)
		}
	}
}

func TestLLMCompileRefusals(t *testing.T) {
	for _, test := range []struct{ name, source string }{
		{"no tokens-per-minute", `<llm-token-limit counter-key="k"/>`},
		{"zero tokens-per-minute", `<llm-token-limit counter-key="k" tokens-per-minute="0"/>`},
		{"unparsable tokens-per-minute", `<llm-token-limit counter-key="k" tokens-per-minute="lots"/>`},
		{"no counter-key", `<llm-token-limit tokens-per-minute="10"/>`},
		{"metric with unparsable tokens-per-minute", `<llm-emit-token-metric tokens-per-minute="lots"><dimension name="d"/></llm-emit-token-metric>`},
		{"dimension with no name", `<llm-emit-token-metric namespace="n"><dimension value="v"/></llm-emit-token-metric>`},
	} {
		if _, err := Compile(`<policies><inbound>`+test.source+`</inbound></policies>`, true); err == nil {
			t.Fatalf("%s compiled", test.name)
		}
	}
	// An unknown child is not a compile failure but an unsupported node, the
	// same treatment every other policy family gets.
	plan, err := Compile(`<policies><inbound><llm-emit-token-metric namespace="n"><nonsense/></llm-emit-token-metric></inbound></policies>`, false)
	if err != nil || plan.Inbound[0].Kind != ActionUnsupported {
		t.Fatalf("unknown child = %v %v", err, plan.Inbound[0].Kind)
	}
	// A namespace-less metric still emits, under a default namespace.
	plan, err = Compile(`<policies><inbound><llm-emit-token-metric><dimension name="d"/></llm-emit-token-metric></inbound></policies>`, true)
	if err != nil || plan.Inbound[0].LLM.Namespace != "llm" {
		t.Fatalf("default namespace = %v %v", err, plan.Inbound[0].LLM)
	}
}

func TestLLMExecutionRefusals(t *testing.T) {
	plan, _ := Compile(`<policies><inbound><llm-token-limit counter-key="k" tokens-per-minute="10"/></inbound></policies>`, true)
	// A gateway that supplied no counter must fail loudly rather than serve
	// every request as though the budget were infinite.
	state := &State{Headers: make(http.Header)}
	if err := Execute(plan.Inbound, state); err == nil {
		t.Fatal("a missing token counter was tolerated")
	}
	// A counter-key that evaluates to nothing would put every caller in one
	// bucket, which is the opposite of a per-caller quota.
	empty, _ := Compile(`<policies><inbound><llm-token-limit counter-key="@(context.Request.Headers.GetValueOrDefault(&quot;X-Absent&quot;,&quot;&quot;))" tokens-per-minute="10"/></inbound></policies>`, true)
	counter := &tokenCounter{allowed: true}
	if err := Execute(empty.Inbound, llmState(counter, `{}`)); err == nil {
		t.Fatal("an empty counter-key was tolerated")
	}
	// A body-less request estimates nothing rather than panicking.
	estimate, _ := Compile(`<policies><inbound><llm-token-limit counter-key="k" tokens-per-minute="10" estimate-prompt-tokens="true"/></inbound></policies>`, true)
	bodyless := &State{Request: &http.Request{}, Headers: make(http.Header), TokenLimit: counter.limit}
	if err := Execute(estimate.Inbound, bodyless); err != nil {
		t.Fatalf("a body-less request failed: %v", err)
	}
}

// failingBody is a request body that cannot be read, which is what a client
// that disconnects mid-upload produces.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errUnreadable }
func (failingBody) Close() error             { return nil }

var errUnreadable = &unreadable{}

type unreadable struct{}

func (*unreadable) Error() string { return "connection reset" }

func TestLLMSurfacesEvaluationAndBodyFailures(t *testing.T) {
	counter := &tokenCounter{remaining: 1, allowed: true}

	// An expression that compiles but cannot evaluate must fail the request
	// rather than silently bucket it under the empty key.
	keyPlan, _ := Compile(`<policies><inbound><llm-token-limit counter-key="@(context.Api.Id)" tokens-per-minute="10"/></inbound></policies>`, true)
	noAPI := llmState(counter, `{}`)
	noAPI.Api = nil
	if err := Execute(keyPlan.Inbound, noAPI); err == nil {
		t.Fatal("an unevaluable counter-key was tolerated")
	}

	// Same for a dimension: a metric emitted under a dimension nobody could
	// compute would be worse than no metric.
	metricPlan, _ := Compile(`<policies><inbound><llm-emit-token-metric namespace="n"><dimension name="d" value="@(context.Api.Id)"/></llm-emit-token-metric></inbound></policies>`, true)
	noAPIMetric := llmState(counter, `{}`)
	noAPIMetric.Api = nil
	if err := Execute(metricPlan.Inbound, noAPIMetric); err == nil {
		t.Fatal("an unevaluable dimension was tolerated")
	}

	// A state that never had a variable map still receives the reported values.
	varPlan, _ := Compile(`<policies><inbound><llm-token-limit counter-key="k" tokens-per-minute="10" remaining-tokens-variable-name="left"/></inbound></policies>`, true)
	noVars := llmState(counter, `{}`)
	noVars.Variables = nil
	if err := Execute(varPlan.Inbound, noVars); err != nil {
		t.Fatal(err)
	}
	if noVars.Variables["left"] != "1" {
		t.Fatalf("variables = %v", noVars.Variables)
	}

	// An unreadable body estimates nothing rather than failing the request:
	// the read failure will surface at the backend, where it belongs.
	estimatePlan, _ := Compile(`<policies><inbound><llm-token-limit counter-key="k" tokens-per-minute="10" estimate-prompt-tokens="true"/></inbound></policies>`, true)
	broken := llmState(counter, `{}`)
	broken.Request.Body = failingBody{}
	if err := Execute(estimatePlan.Inbound, broken); err != nil {
		t.Fatalf("an unreadable body failed the policy: %v", err)
	}
}

// TestLLMTokenQuota covers the budget Microsoft documents alongside the
// per-minute rate: "Either a rate limit (tokens-per-minute), a quota
// (token-quota over a token-quota-period), or both must be specified."
func TestLLMTokenQuota(t *testing.T) {
	// A quota-only policy is valid. It used to be refused for having no
	// tokens-per-minute, which is a policy Azure accepts.
	quotaOnly, err := Compile(`<policies><inbound><llm-token-limit counter-key="k" token-quota="1000" token-quota-period="Monthly"/></inbound></policies>`, true)
	if err != nil {
		t.Fatalf("a quota-only policy was refused: %v", err)
	}
	if quotaOnly.Inbound[0].LLM.TokenQuota != "1000" || quotaOnly.Inbound[0].LLM.TokenQuotaPeriod != "Monthly" {
		t.Fatalf("quota-only config = %+v", quotaOnly.Inbound[0].LLM)
	}

	// Half a quota is not a quota, and neither half alone is a policy.
	for _, attrs := range []string{
		`counter-key="k" token-quota="1000"`,
		// With a rate present, half a quota is still not a quota.
		`counter-key="k" tokens-per-minute="10" token-quota="1000"`,
		`counter-key="k" tokens-per-minute="10" token-quota-period="Daily"`,
		`counter-key="k" token-quota-period="Monthly"`,
		`counter-key="k"`,
		`counter-key="k" tokens-per-minute="10" token-quota="1000" token-quota-period="Fortnightly"`,
		`counter-key="k" tokens-per-minute="10" token-quota="nope" token-quota-period="Daily"`,
		`counter-key="k" tokens-per-minute="10" token-quota="0" token-quota-period="Daily"`,
	} {
		if _, err := Compile(`<policies><inbound><llm-token-limit `+attrs+`/></inbound></policies>`, true); err == nil {
			t.Errorf("accepted %s", attrs)
		}
	}

	// The quota refuses a request the rate would have allowed, and reports the
	// remainder a policy asked for.
	plan, err := Compile(`<policies><inbound><llm-token-limit counter-key="k" tokens-per-minute="1000000"`+
		` token-quota="500" token-quota-period="Daily" remaining-quota-tokens-header-name="X-Quota-Left"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	var asked []string
	state := &State{
		Headers:    make(http.Header),
		Request:    httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}")),
		TokenLimit: func(string, int, int) (int, int, bool) { return 999999, 0, true },
		TokenQuota: func(key string, quota int, period string, _ int) (int, int, bool) {
			asked = append(asked, period)
			return 0, 3600, false
		},
	}
	if err := Execute(plan.Inbound, state); err != nil {
		t.Fatal(err)
	}
	if !state.Returned || state.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the quota did not refuse the request: %+v", state)
	}
	if state.Headers.Get("X-Quota-Left") != "0" {
		t.Fatalf("remaining-quota-tokens-header-name = %q", state.Headers.Get("X-Quota-Left"))
	}
	if len(asked) != 1 || asked[0] != "Daily" {
		t.Fatalf("the counter was asked for period %v", asked)
	}

	// An expression period reaches the counter EVALUATED. Handing it the
	// compiled expression would leave the runtime unable to place the window,
	// and a quota that charges nothing looks exactly like a generous one.
	exprPlan, err := Compile(`<policies><inbound><llm-token-limit counter-key="k" token-quota="@(500)" token-quota-period="@(&quot;Daily&quot;)"/></inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	asked = nil
	var quotas []int
	exprState := &State{
		Headers: make(http.Header),
		Request: httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}")),
		TokenQuota: func(_ string, quota int, period string, _ int) (int, int, bool) {
			asked = append(asked, period)
			quotas = append(quotas, quota)
			return 500, 0, true
		},
	}
	if err := Execute(exprPlan.Inbound, exprState); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != "Daily" || len(quotas) != 1 || quotas[0] != 500 {
		t.Fatalf("expression quota reached the counter as %v / %v", asked, quotas)
	}
	// And the evaluated period is what the response accounting will charge.
	if exprState.LLM == nil || exprState.LLM.QuotaPeriod != "Daily" || exprState.LLM.Quota != 500 {
		t.Fatalf("governance carried %+v, want the evaluated period and quota", exprState.LLM)
	}

	// An expression that evaluates to nonsense stops the request rather than
	// governing nothing.
	for _, attrs := range []string{
		`counter-key="k" token-quota="@(&quot;lots&quot;)" token-quota-period="Daily"`,
		// An expression that cannot be evaluated at all, in either attribute.
		`counter-key="k" token-quota="@(1 / 0)" token-quota-period="Daily"`,
		`counter-key="k" token-quota="@(500)" token-quota-period="@(1 / 0)"`,
		`counter-key="k" token-quota="@(500)" token-quota-period="@(&quot;Fortnightly&quot;)"`,
	} {
		bad, err := Compile(`<policies><inbound><llm-token-limit `+attrs+`/></inbound></policies>`, true)
		if err != nil {
			t.Fatalf("%s: %v", attrs, err)
		}
		badState := &State{Headers: make(http.Header), Request: httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}")),
			TokenQuota: func(string, int, string, int) (int, int, bool) { return 0, 0, true }}
		if err := Execute(bad.Inbound, badState); err == nil {
			t.Errorf("%s governed nothing without reporting a failure", attrs)
		}
	}

	// A quota policy needs a quota counter.
	if err := Execute(quotaOnly.Inbound, &State{Headers: make(http.Header), Request: httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))}); err == nil {
		t.Fatal("a token-quota ran with no counter configured")
	}
}

// TestLLMEmitTokenMetricDimensionCap covers the limit the reference states:
// "You can configure at most 5 custom dimensions for this policy."
func TestLLMEmitTokenMetricDimensionCap(t *testing.T) {
	build := func(count int) string {
		var dimensions strings.Builder
		for i := 0; i < count; i++ {
			dimensions.WriteString(`<dimension name="d` + string(rune('A'+i)) + `"/>`)
		}
		return `<policies><inbound><llm-emit-token-metric namespace="n">` + dimensions.String() + `</llm-emit-token-metric></inbound></policies>`
	}
	plan, err := Compile(build(5), true)
	if err != nil {
		t.Fatalf("five dimensions were refused: %v", err)
	}
	if len(plan.Inbound[0].LLM.Dimensions) != 5 {
		t.Fatalf("five dimensions compiled to %d", len(plan.Inbound[0].LLM.Dimensions))
	}
	if _, err := Compile(build(6), true); err == nil {
		t.Fatal("six dimensions were accepted, where Azure allows five")
	}
}
