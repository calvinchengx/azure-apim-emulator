package policy

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/llm"
)

// Token governance for model APIs: `llm-token-limit` and
// `llm-emit-token-metric`.
//
// Both depend on a fact the rest of the policy engine does not have to face: a
// model's token count is only known AFTER it answers, and for a streamed answer
// it arrives on a chunk near the end of the body. An outbound policy cannot see
// that body -- it is written to the caller as it arrives -- so these actions
// record their INTENT on the state and the gateway does the counting on the way
// past. See LLMGovernance below.

// LLMConfig is the compiled configuration of one token-governance node.
type LLMConfig struct {
	CounterKey      string
	TokensPerMinute int
	// EstimatePromptTokens asks for a decision BEFORE the model answers, which
	// the emulator can only approximate. See llm.Estimate: with this false,
	// every number comes from the provider and is exact.
	EstimatePromptTokens bool
	RetryAfterHeader     string
	RetryAfterVariable   string
	// TokenQuota is a budget over a fixed period, beside the per-minute rate.
	// Held compiled because policy expressions are allowed in both, and a
	// policy may set the quota, the rate, or both.
	TokenQuota             string
	TokenQuotaPeriod       string
	RemainingQuotaHeader   string
	RemainingQuotaVariable string
	RemainingHeader        string
	RemainingVariable      string
	ConsumedHeader         string
	ConsumedVariable       string
	Namespace              string
	Dimensions             []LLMDimension
}

// LLMDimension is one `<dimension>` child of an emit-token-metric node.
type LLMDimension struct{ Name, Value string }

// LLMGovernance is what an executed token-governance action leaves on the state
// for the gateway to act on once the model has answered.
//
// It exists because the decision and the accounting happen at different times:
// the limit is enforced on the way in, from what previous requests spent, and
// what THIS request spent is only knowable on the way out.
type LLMGovernance struct {
	CounterKey      string
	TokensPerMinute int
	Config          LLMConfig
	// QuotaPeriod and Quota are the EVALUATED token-quota settings. The Config
	// holds them compiled, and both allow policy expressions, so charging the
	// spend from Config would hand the runtime an expression rather than a
	// period and quietly charge nothing.
	QuotaPeriod string
	Quota       int
	// Emit is set when an emit-token-metric node ran, with its dimensions
	// already evaluated against the request.
	Emit       bool
	Namespace  string
	Dimensions map[string]string
}

func compileLLMTokenLimit(item node) (Action, bool, error) {
	config, err := compileLLMConfig(item)
	if err != nil {
		return Action{}, false, err
	}
	// "Either a rate limit (tokens-per-minute), a quota (token-quota over a
	// token-quota-period), or both must be specified." Requiring the rate
	// unconditionally refused a quota-only policy that Azure accepts.
	hasQuota := config.TokenQuota != "" && config.TokenQuotaPeriod != ""
	if config.TokensPerMinute <= 0 && !hasQuota {
		return Action{}, false, fmt.Errorf("llm-token-limit requires tokens-per-minute, or token-quota over a token-quota-period")
	}
	// Half a quota is not a quota: a period with no budget, or a budget with no
	// period, would enforce nothing while looking configured.
	if (config.TokenQuota == "") != (config.TokenQuotaPeriod == "") {
		return Action{}, false, fmt.Errorf("llm-token-limit needs token-quota and token-quota-period together")
	}
	if config.CounterKey == "" {
		return Action{}, false, fmt.Errorf("llm-token-limit requires a counter-key")
	}
	return Action{Kind: ActionLLMTokenLimit, LLM: config, StatusCode: http.StatusTooManyRequests}, true, nil
}

func compileLLMEmitTokenMetric(item node) (Action, bool, error) {
	config, err := compileLLMConfig(item)
	if err != nil {
		return Action{}, false, err
	}
	for _, child := range item.Children {
		if child.Name != "dimension" {
			return unsupported(item.Name + "/" + child.Name), true, nil
		}
		name := child.Attrs["name"]
		if name == "" {
			return Action{}, false, fmt.Errorf("llm-emit-token-metric dimension requires a name")
		}
		value := child.Attrs["value"]
		if value == "" {
			value = name
		}
		config.Dimensions = append(config.Dimensions, LLMDimension{Name: name, Value: value})
	}
	// "You can configure at most 5 custom dimensions for this policy." A sixth
	// is a policy Azure refuses, so accepting it here would emit a metric shape
	// the tenant will not.
	if len(config.Dimensions) > 5 {
		return Action{}, false, fmt.Errorf("llm-emit-token-metric takes at most 5 dimensions, got %d", len(config.Dimensions))
	}
	if config.Namespace == "" {
		config.Namespace = "llm"
	}
	return Action{Kind: ActionLLMEmitTokenMetric, LLM: config}, true, nil
}

func compileLLMConfig(item node) (LLMConfig, error) {
	config := LLMConfig{
		CounterKey:             item.Attrs["counter-key"],
		EstimatePromptTokens:   strings.EqualFold(item.Attrs["estimate-prompt-tokens"], "true"),
		RetryAfterHeader:       item.Attrs["retry-after-header-name"],
		RetryAfterVariable:     item.Attrs["retry-after-variable-name"],
		TokenQuota:             item.Attrs["token-quota"],
		TokenQuotaPeriod:       item.Attrs["token-quota-period"],
		RemainingQuotaHeader:   item.Attrs["remaining-quota-tokens-header-name"],
		RemainingQuotaVariable: item.Attrs["remaining-quota-tokens-variable-name"],
		RemainingHeader:        item.Attrs["remaining-tokens-header-name"],
		RemainingVariable:      item.Attrs["remaining-tokens-variable-name"],
		ConsumedHeader:         item.Attrs["tokens-consumed-header-name"],
		ConsumedVariable:       item.Attrs["tokens-consumed-variable-name"],
		Namespace:              item.Attrs["namespace"],
	}
	if raw := item.Attrs["tokens-per-minute"]; raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			return LLMConfig{}, fmt.Errorf("invalid tokens-per-minute %q", raw)
		}
		config.TokensPerMinute = value
	}
	// A literal period must be one of the five Microsoft names. An expression
	// is checked when it runs, since its value is not known yet.
	if period := config.TokenQuotaPeriod; period != "" && !expression(period) {
		if !validQuotaPeriod(period) {
			return LLMConfig{}, fmt.Errorf("invalid token-quota-period %q", period)
		}
	}
	if quota := config.TokenQuota; quota != "" && !expression(quota) {
		value, err := strconv.Atoi(strings.TrimSpace(quota))
		if err != nil || value <= 0 {
			return LLMConfig{}, fmt.Errorf("invalid token-quota %q", quota)
		}
	}
	return config, nil
}

// quotaPeriods are the window lengths token-quota-period accepts. Microsoft
// names exactly these five, and the start of a period is "the UTC timestamp
// truncated to the unit" rather than the moment the first request arrived.
var quotaPeriods = []string{"Hourly", "Daily", "Weekly", "Monthly", "Yearly"}

func validQuotaPeriod(period string) bool {
	for _, name := range quotaPeriods {
		if strings.EqualFold(strings.TrimSpace(period), name) {
			return true
		}
	}
	return false
}

func executeLLMTokenLimit(action Action, state *State) error {
	if action.LLM.TokensPerMinute > 0 && state.TokenLimit == nil {
		return fmt.Errorf("llm-token-limit requires a configured token counter")
	}
	if action.LLM.TokenQuota != "" && state.TokenQuota == nil {
		return fmt.Errorf("llm-token-limit token-quota requires a configured quota counter")
	}
	key, err := evalValue(action.LLM.CounterKey, state)
	if err != nil {
		return err
	}
	// A counter-key that evaluates to nothing would put every caller in one
	// bucket, which is the opposite of what a per-caller quota is for.
	if key == "" {
		return fmt.Errorf("llm-token-limit counter-key evaluated to empty")
	}
	estimate := 0
	if action.LLM.EstimatePromptTokens {
		estimate = llm.Estimate(requestBodyBytes(state))
	}
	remaining, retryAfter, allowed := 0, 0, true
	if action.LLM.TokensPerMinute > 0 {
		remaining, retryAfter, allowed = state.TokenLimit(key, action.LLM.TokensPerMinute, estimate)
	}
	// The quota is a second budget. It is consulted even when the rate already
	// refused, so the remaining-quota counters a policy asked for are reported
	// either way, and it can refuse a request the rate would have allowed.
	quotaRemaining, quotaRetry, quotaAllowed, resolved, err := applyTokenQuota(action, state, key, estimate)
	if err != nil {
		return err
	}
	if action.LLM.TokenQuota != "" {
		setLLMValue(state, action.LLM.RemainingQuotaHeader, action.LLM.RemainingQuotaVariable, strconv.Itoa(quotaRemaining))
		if !quotaAllowed && allowed {
			allowed, retryAfter = false, quotaRetry
		}
	}
	governance := &LLMGovernance{CounterKey: key, TokensPerMinute: action.LLM.TokensPerMinute, Config: action.LLM,
		QuotaPeriod: resolved.period, Quota: resolved.quota}
	if existing := state.LLM; existing != nil {
		governance.Emit, governance.Namespace, governance.Dimensions = existing.Emit, existing.Namespace, existing.Dimensions
	}
	state.LLM = governance
	setLLMValue(state, action.LLM.RemainingHeader, action.LLM.RemainingVariable, strconv.Itoa(remaining))
	if allowed {
		return nil
	}
	setLLMValue(state, action.LLM.RetryAfterHeader, action.LLM.RetryAfterVariable, strconv.Itoa(retryAfter))
	state.Returned, state.StatusCode = true, action.StatusCode
	// Retry-After is sent whether or not the policy named a custom header for
	// it: a 429 without one tells a client to guess, and every HTTP client
	// library knows the standard header.
	state.Headers.Set("Retry-After", strconv.Itoa(retryAfter))
	return nil
}

func executeLLMEmitTokenMetric(action Action, state *State) error {
	dimensions := map[string]string{}
	for _, dimension := range action.LLM.Dimensions {
		value, err := evalValue(dimension.Value, state)
		if err != nil {
			return err
		}
		dimensions[dimension.Name] = value
	}
	if state.LLM == nil {
		state.LLM = &LLMGovernance{}
	}
	state.LLM.Emit, state.LLM.Namespace, state.LLM.Dimensions = true, action.LLM.Namespace, dimensions
	return nil
}

// setLLMValue writes one governance number to wherever the policy asked for it.
// Both destinations are optional and independent: Azure lets a policy surface a
// number to the caller, to later policy expressions, to both, or to neither.
func setLLMValue(state *State, header, variable, value string) {
	if header != "" && state.Headers != nil {
		state.Headers.Set(header, value)
	}
	if variable != "" {
		if state.Variables == nil {
			state.Variables = map[string]string{}
		}
		state.Variables[variable] = value
	}
}

// requestBodyBytes reads the request body for estimation and puts it back.
//
// Consuming it would leave the backend with an empty prompt, which is the kind
// of damage a policy that only MEASURES must never do.
func requestBodyBytes(state *State) []byte {
	if state.Request == nil || state.Request.Body == nil {
		return nil
	}
	body, err := io.ReadAll(state.Request.Body)
	if err != nil {
		return nil
	}
	_ = state.Request.Body.Close()
	state.Request.Body = io.NopCloser(strings.NewReader(string(body)))
	state.Request.ContentLength = int64(len(body))
	return body
}

// applyTokenQuota evaluates the token-quota attributes and consults the quota
// counter. A policy without a quota gets an allowing answer and nothing else.
type resolvedQuota struct {
	period string
	quota  int
}

func applyTokenQuota(action Action, state *State, key string, estimate int) (int, int, bool, resolvedQuota, error) {
	if action.LLM.TokenQuota == "" {
		return 0, 0, true, resolvedQuota{}, nil
	}
	rendered, err := evalValue(action.LLM.TokenQuota, state)
	if err != nil {
		return 0, 0, false, resolvedQuota{}, err
	}
	quota, convErr := strconv.Atoi(strings.TrimSpace(rendered))
	if convErr != nil || quota <= 0 {
		return 0, 0, false, resolvedQuota{}, fmt.Errorf("invalid token-quota %q", rendered)
	}
	period, err := evalValue(action.LLM.TokenQuotaPeriod, state)
	if err != nil {
		return 0, 0, false, resolvedQuota{}, err
	}
	if !validQuotaPeriod(period) {
		return 0, 0, false, resolvedQuota{}, fmt.Errorf("invalid token-quota-period %q", period)
	}
	remaining, retryAfter, allowed := state.TokenQuota(key, quota, period, estimate)
	return remaining, retryAfter, allowed, resolvedQuota{period: period, quota: quota}, nil
}
