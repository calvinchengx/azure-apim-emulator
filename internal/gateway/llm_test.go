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
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

// openAIBackend answers like a model API: a usage object on a JSON completion,
// and a usage-bearing final chunk on a stream.
// streamBody is the exact stream openAIBackend emits, so a test can compare
// against it rather than against landmarks inside it.
func streamBody(promptTokens, completionTokens int) string {
	usage := fmt.Sprintf(`{"prompt_tokens":%d,"completion_tokens":%d,"total_tokens":%d}`,
		promptTokens, completionTokens, promptTokens+completionTokens)
	return "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}],\"usage\":null}\n\n" +
		"data: {\"choices\":[],\"usage\":" + usage + "}\n\n" +
		"data: [DONE]\n\n"
}

func openAIBackend(t *testing.T, promptTokens, completionTokens int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var request struct {
			Stream bool `json:"stream"`
		}
		_ = json.Unmarshal(body, &request)
		usage := fmt.Sprintf(`{"prompt_tokens":%d,"completion_tokens":%d,"total_tokens":%d}`,
			promptTokens, completionTokens, promptTokens+completionTokens)
		if request.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}],\"usage\":null}\n\n")
			fmt.Fprintf(w, "data: {\"choices\":[],\"usage\":%s}\n\n", usage)
			fmt.Fprintf(w, "data: [DONE]\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"choices":[{"message":{"content":"hi"}}],"usage":%s}`, usage)
	}))
	t.Cleanup(server.Close)
	return server
}

func llmRuntime(t *testing.T, backend string, policyXML string) *Runtime {
	t.Helper()
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	if err != nil {
		t.Fatal(err)
	}
	api, err := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "openai", DisplayName: "OpenAI", Path: "openai", ServiceURL: backend, IsCurrent: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "chat", DisplayName: "Chat", Method: http.MethodPost, URLTemplate: "/chat/completions"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: policyXML}); err != nil {
		t.Fatal(err)
	}
	runtime := New("emulator", nil)
	if err := runtime.Activate(st, true); err != nil {
		t.Fatal(err)
	}
	return runtime
}

func chatRequest(stream bool) *http.Request {
	body := `{"messages":[{"role":"user","content":"hello"}]}`
	if stream {
		body = `{"stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"hello"}]}`
	}
	request := httptest.NewRequest(http.MethodPost, "/openai/chat/completions", strings.NewReader(body))
	request.RemoteAddr = "10.0.0.8:5000"
	return request
}

// A non-streamed answer's counts reach the caller on the SAME response they
// describe, because the body can be read before it is written.
func TestLLMTokenLimitReportsConsumptionOnTheResponse(t *testing.T) {
	backend := openAIBackend(t, 30, 20)
	runtime := llmRuntime(t, backend.URL, `<policies><inbound><llm-token-limit counter-key="tenant" tokens-per-minute="1000" tokens-consumed-header-name="x-consumed" remaining-tokens-header-name="x-remaining"/></inbound></policies>`)

	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, chatRequest(false))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("x-consumed"); got != "50" {
		t.Fatalf("consumed header = %q", got)
	}
	// 1000 budget less the 50 just spent.
	if got := recorder.Header().Get("x-remaining"); got != "950" {
		t.Fatalf("remaining header = %q", got)
	}
	// The body reaches the caller unaltered despite having been read to count.
	if !strings.Contains(recorder.Body.String(), `"total_tokens":50`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}

// Enforcement is one request behind, and that is faithful rather than a
// shortcut: with estimate-prompt-tokens false, Azure cannot know a request's
// cost until the model has answered either.
func TestLLMTokenLimitRefusesTheRequestAfterTheBudgetIsSpent(t *testing.T) {
	backend := openAIBackend(t, 40, 40)
	runtime := llmRuntime(t, backend.URL, `<policies><inbound><llm-token-limit counter-key="tenant" tokens-per-minute="100"/></inbound></policies>`)

	first := httptest.NewRecorder()
	runtime.ServeHTTP(first, chatRequest(false))
	if first.Code != http.StatusOK {
		t.Fatalf("first request = %d", first.Code)
	}
	second := httptest.NewRecorder()
	runtime.ServeHTTP(second, chatRequest(false))
	if second.Code != http.StatusOK {
		t.Fatalf("second request = %d (80 of 100 spent, it should still fit)", second.Code)
	}
	third := httptest.NewRecorder()
	runtime.ServeHTTP(third, chatRequest(false))
	if third.Code != http.StatusTooManyRequests {
		t.Fatalf("third request = %d, want 429 (160 of 100 spent)", third.Code)
	}
	if third.Header().Get("Retry-After") == "" {
		t.Fatal("a 429 with no Retry-After tells the client to guess")
	}
}

// A streamed answer is counted on the way past. The bytes must be untouched and
// the accounting must still land, which is the whole reason it is not an
// outbound policy.
func TestLLMTokenLimitCountsStreamedAnswers(t *testing.T) {
	backend := openAIBackend(t, 60, 60)
	runtime := llmRuntime(t, backend.URL, `<policies><inbound><llm-token-limit counter-key="tenant" tokens-per-minute="100"/></inbound></policies>`)

	first := httptest.NewRecorder()
	runtime.ServeHTTP(first, chatRequest(true))
	if first.Code != http.StatusOK {
		t.Fatalf("streamed request = %d", first.Code)
	}
	// Byte-identical, not merely containing the landmarks: the counter tees the
	// stream, and a tee that drops or reorders a byte is exactly the defect
	// this assertion exists to catch. A substring check passes while dropping
	// the trailing newline of every chunk.
	if got := first.Body.String(); got != streamBody(60, 60) {
		t.Fatalf("the stream was altered:\n got %q\nwant %q", got, streamBody(60, 60))
	}
	// 120 tokens went past on a 100 budget, so the next request is refused.
	// Without counting the stream this would be 200.
	second := httptest.NewRecorder()
	runtime.ServeHTTP(second, chatRequest(true))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("after a 120-token stream on a 100 budget = %d, want 429", second.Code)
	}
}

// A caller who never asked for usage gets none, and the emulator must not
// invent a number for it.
func TestLLMTokenLimitDoesNotInventStreamUsage(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n")
	}))
	defer backend.Close()
	runtime := llmRuntime(t, backend.URL, `<policies><inbound><llm-token-limit counter-key="tenant" tokens-per-minute="10"/></inbound></policies>`)
	for attempt := range 3 {
		recorder := httptest.NewRecorder()
		runtime.ServeHTTP(recorder, chatRequest(true))
		if recorder.Code != http.StatusOK {
			t.Fatalf("attempt %d = %d: an uncounted stream must not accumulate", attempt, recorder.Code)
		}
	}
}

func TestLLMEmitTokenMetric(t *testing.T) {
	backend := openAIBackend(t, 12, 8)
	runtime := llmRuntime(t, backend.URL, `<policies><inbound><llm-token-limit counter-key="tenant" tokens-per-minute="1000"/><llm-emit-token-metric namespace="contoso"><dimension name="API ID" value="@(context.Api.Id)"/><dimension name="Client"/></llm-emit-token-metric></inbound></policies>`)

	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, chatRequest(false))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	metrics := runtime.TokenMetrics()
	if len(metrics) != 1 {
		t.Fatalf("metrics = %#v", metrics)
	}
	metric := metrics[0]
	if metric.Namespace != "contoso" || metric.PromptTokens != 12 || metric.CompletionTokens != 8 || metric.TotalTokens != 20 {
		t.Fatalf("metric = %#v", metric)
	}
	// context.Api.Id is the API IDENTIFIER, not its ARM resource path, which is
	// what Azure's expression returns too.
	if metric.Dimensions["Client"] != "Client" || metric.Dimensions["API ID"] != "openai" {
		t.Fatalf("dimensions = %v", metric.Dimensions)
	}
}

// The counter is per key, so one tenant exhausting its budget must not refuse
// another's request.
func TestLLMTokenBudgetsAreIndependentPerCounterKey(t *testing.T) {
	backend := openAIBackend(t, 60, 60)
	runtime := llmRuntime(t, backend.URL, `<policies><inbound><llm-token-limit counter-key="@(context.Request.Headers.GetValueOrDefault(&quot;X-Tenant&quot;,&quot;anonymous&quot;))" tokens-per-minute="100"/></inbound></policies>`)

	spend := func(tenant string) int {
		request := chatRequest(false)
		request.Header.Set("X-Tenant", tenant)
		recorder := httptest.NewRecorder()
		runtime.ServeHTTP(recorder, request)
		return recorder.Code
	}
	if code := spend("alpha"); code != http.StatusOK {
		t.Fatalf("alpha first = %d", code)
	}
	if code := spend("alpha"); code != http.StatusTooManyRequests {
		t.Fatalf("alpha second = %d, want 429", code)
	}
	if code := spend("beta"); code != http.StatusOK {
		t.Fatalf("beta first = %d: one tenant's spend refused another's request", code)
	}
}

// A limit with estimation charges before the model answers, so a single
// oversized prompt is refused on the request that follows it without the
// backend ever being consulted about cost.
func TestLLMTokenLimitEstimatesUpFront(t *testing.T) {
	backend := openAIBackend(t, 1, 1)
	runtime := llmRuntime(t, backend.URL, `<policies><inbound><llm-token-limit counter-key="tenant" tokens-per-minute="6" estimate-prompt-tokens="true"/></inbound></policies>`)
	first := httptest.NewRecorder()
	runtime.ServeHTTP(first, chatRequest(false))
	if first.Code != http.StatusOK {
		t.Fatalf("first = %d", first.Code)
	}
	second := httptest.NewRecorder()
	runtime.ServeHTTP(second, chatRequest(false))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second = %d, want 429: the estimate plus the reported usage should exceed 6", second.Code)
	}
}

// A response that carries no usage at all leaves the counter untouched rather
// than charging zero or guessing.
func TestLLMTokenLimitIgnoresResponsesWithoutUsage(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer backend.Close()
	runtime := llmRuntime(t, backend.URL, `<policies><inbound><llm-token-limit counter-key="tenant" tokens-per-minute="10" tokens-consumed-header-name="x-consumed"/></inbound></policies>`)
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, chatRequest(false))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if recorder.Header().Get("x-consumed") != "" {
		t.Fatalf("a usage-less answer reported a consumption: %q", recorder.Header().Get("x-consumed"))
	}
}

// The sliding window itself, exercised directly. The paths below are reachable
// only through argument combinations the policy compiler refuses to produce, or
// through a backend failing mid-body, so driving them over HTTP would mean
// weakening a validation to reach them.
func TestTokenWindowArithmetic(t *testing.T) {
	runtime := New("emulator", nil)

	// An estimate larger than the headroom clamps at zero rather than
	// reporting a negative budget to the caller.
	remaining, _, allowed := runtime.tokenLimit("k", 10, 400)
	if !allowed || remaining != 0 {
		t.Fatalf("oversized estimate = %d %v", remaining, allowed)
	}
	// ...and it was still charged, so the next request is refused.
	if _, retryAfter, allowed := runtime.tokenLimit("k", 10, 0); allowed || retryAfter < 1 {
		t.Fatalf("after an oversized estimate: allowed=%v retryAfter=%d", allowed, retryAfter)
	}
	if got := runtime.tokensRemaining("k", 10); got != 0 {
		t.Fatalf("remaining on an exhausted key = %d", got)
	}

	// A model reporting no tokens leaves the window alone: charging zero would
	// still stamp the window and could shift a later Retry-After.
	before := len(runtime.tokenWindows["quiet"])
	runtime.recordTokens("quiet", 0)
	if len(runtime.tokenWindows["quiet"]) != before {
		t.Fatal("a zero-token answer was recorded")
	}
}

// A body that fails mid-read must not be counted, and must not panic the
// accounting: the failure surfaces to the caller as a truncated response, which
// is what actually happened.
func TestGovernLLMResponseSurvivesAnUnreadableBody(t *testing.T) {
	runtime := New("emulator", nil)
	response := &http.Response{
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   io.NopCloser(brokenReader{}),
	}
	state := &policy.State{Headers: make(http.Header), LLM: &policy.LLMGovernance{CounterKey: "tenant", TokensPerMinute: 100}}
	finish := runtime.governLLMResponse(response, state)
	finish()
	if len(runtime.tokenWindows["tenant"]) != 0 {
		t.Fatal("an unreadable body was charged")
	}
}

// Nothing runs when no token policy was in the plan, which is the common case
// for every non-model API on the gateway.
func TestGovernLLMResponseIsInertWithoutAPolicy(t *testing.T) {
	runtime := New("emulator", nil)
	runtime.governLLMResponse(&http.Response{Body: io.NopCloser(strings.NewReader("{}"))}, &policy.State{Headers: make(http.Header)})()
	if len(runtime.TokenMetrics()) != 0 {
		t.Fatal("a metric was emitted with no policy")
	}
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errBroken }

var errBroken = &brokenError{}

type brokenError struct{}

func (*brokenError) Error() string { return "connection reset" }
