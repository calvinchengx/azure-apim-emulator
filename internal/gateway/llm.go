package gateway

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/calvinchengx/azure-apim-emulator/internal/llm"
	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
)

// Token governance for model APIs.
//
// The awkward fact this has to accommodate: a model reports what a request cost
// only once it has answered, and for a streamed answer that number arrives on a
// chunk near the end of the body. So the limit decision and the accounting
// happen at different moments, against the same sliding window.
//
// The consequence is that the ENFORCEMENT is faithful while being one request
// behind: a request that blows the budget is served, and the request after it is
// refused. That is also what Azure does when `estimate-prompt-tokens` is false,
// and it is why the attribute exists at all.

// tokenStamp is one accounted spend inside the counter's window.
type tokenStamp struct {
	at     time.Time
	tokens int
}

// tokenLimit reports the tokens left on a counter key and whether the request
// may proceed.
//
// The estimate is charged immediately when the policy asked for one, so that a
// caller cannot spend the whole budget in a burst that all arrives before any
// answer does. With no estimate, the window contains only what previous
// requests actually spent.
func (r *Runtime) tokenLimit(key string, tokensPerMinute, estimate int) (int, int, bool) {
	now := time.Now()
	r.rateMu.Lock()
	defer r.rateMu.Unlock()
	window, oldest := r.trimTokenWindow(key, now)
	spent := 0
	for _, stamp := range window {
		spent += stamp.tokens
	}
	remaining := tokensPerMinute - spent
	if remaining < 0 {
		remaining = 0
	}
	if spent >= tokensPerMinute {
		// Retry-After is when the oldest spend leaves the window, which is the
		// first moment the caller could succeed. Rounding up matters: telling a
		// client to retry at the instant the window moves invites it to arrive
		// a millisecond early and be refused again.
		// Every kept stamp is newer than the cutoff, so this is always at least
		// one second; no floor is needed, and adding one would be dead code.
		return 0, int(oldest.Add(time.Minute).Sub(now).Seconds()) + 1, false
	}
	if estimate > 0 {
		r.tokenWindows[key] = append(window, tokenStamp{at: now, tokens: estimate})
		remaining -= estimate
		if remaining < 0 {
			remaining = 0
		}
	} else {
		r.tokenWindows[key] = window
	}
	return remaining, 0, true
}

// trimTokenWindow drops spends older than a minute and reports the oldest kept.
func (r *Runtime) trimTokenWindow(key string, now time.Time) ([]tokenStamp, time.Time) {
	window := r.tokenWindows[key]
	cutoff := now.Add(-time.Minute)
	kept := window[:0]
	oldest := now
	for _, stamp := range window {
		if stamp.at.After(cutoff) {
			kept = append(kept, stamp)
			if stamp.at.Before(oldest) {
				oldest = stamp.at
			}
		}
	}
	return kept, oldest
}

// recordTokens charges a counter key for what a request actually spent.
func (r *Runtime) recordTokens(key string, tokens int) {
	if tokens <= 0 {
		return
	}
	now := time.Now()
	r.rateMu.Lock()
	defer r.rateMu.Unlock()
	window, _ := r.trimTokenWindow(key, now)
	r.tokenWindows[key] = append(window, tokenStamp{at: now, tokens: tokens})
}

// governLLMResponse completes the token accounting a policy started.
//
// Non-streamed answers are buffered so the usage object can be read before the
// response is written, which is what lets the consumed and remaining counts
// reach the caller as headers on the SAME response they describe. A streamed
// answer cannot be treated that way -- buffering it would destroy the streaming
// the caller asked for -- so it is counted on the way past and the numbers reach
// the caller only through the next request's headers. The distinction is
// visible rather than smoothed over, because a header that silently stops
// appearing is worse than one that was never promised.
// It returns a function to run once the body has been written, which is the
// only moment a streamed answer's total is knowable. The caller must invoke it;
// returning it rather than deferring inside keeps the accounting off the
// Runtime, which is shared by every concurrent request.
func (r *Runtime) governLLMResponse(response *http.Response, state *policy.State) func() {
	governance := state.LLM
	if governance == nil || response == nil || response.Body == nil {
		return func() {}
	}
	if llm.IsEventStream(response.Header.Get("Content-Type")) {
		counter := llm.NewStreamCounter(response.Body)
		response.Body = struct {
			io.Reader
			io.Closer
		}{Reader: counter, Closer: response.Body}
		return func() {
			if usage, ok := counter.Usage(); ok {
				r.finishLLMAccounting(governance, usage, nil)
			}
		}
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		return func() {}
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	if usage, ok := llm.UsageFromBody(body); ok {
		r.finishLLMAccounting(governance, usage, state.Headers)
	}
	return func() {}
}

// finishLLMAccounting charges the counter and reports the spend.
func (r *Runtime) finishLLMAccounting(governance *policy.LLMGovernance, usage llm.Usage, headers http.Header) {
	total := usage.Total()
	if governance.CounterKey != "" {
		r.recordTokens(governance.CounterKey, total)
	}
	if headers != nil {
		if name := governance.Config.ConsumedHeader; name != "" {
			headers.Set(name, strconv.Itoa(total))
		}
		if name := governance.Config.RemainingHeader; name != "" && governance.TokensPerMinute > 0 {
			headers.Set(name, strconv.Itoa(r.tokensRemaining(governance.CounterKey, governance.TokensPerMinute)))
		}
	}
	if governance.Emit {
		r.emitTokenMetric(governance, usage)
	}
}

// tokensRemaining reports a counter key's headroom without charging it.
func (r *Runtime) tokensRemaining(key string, tokensPerMinute int) int {
	now := time.Now()
	r.rateMu.Lock()
	defer r.rateMu.Unlock()
	window, _ := r.trimTokenWindow(key, now)
	r.tokenWindows[key] = window
	spent := 0
	for _, stamp := range window {
		spent += stamp.tokens
	}
	if remaining := tokensPerMinute - spent; remaining > 0 {
		return remaining
	}
	return 0
}

// TokenMetric is one emitted token-consumption measurement.
type TokenMetric struct {
	Namespace        string
	Dimensions       map[string]string
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
}

func (r *Runtime) emitTokenMetric(governance *policy.LLMGovernance, usage llm.Usage) {
	r.metricMu.Lock()
	defer r.metricMu.Unlock()
	r.tokenMetrics = append(r.tokenMetrics, TokenMetric{
		Namespace:        governance.Namespace,
		Dimensions:       governance.Dimensions,
		PromptTokens:     usage.PromptTokens,
		CompletionTokens: usage.CompletionTokens,
		TotalTokens:      usage.Total(),
	})
}

// TokenMetrics returns the emitted measurements, most recent last.
//
// Azure sends these to Application Insights. The emulator keeps them in memory
// and serves them from the control surface instead, because a metric nobody can
// read is indistinguishable from one that was never emitted, and a test that
// cannot see it proves nothing.
func (r *Runtime) TokenMetrics() []TokenMetric {
	r.metricMu.Lock()
	defer r.metricMu.Unlock()
	return append([]TokenMetric(nil), r.tokenMetrics...)
}
