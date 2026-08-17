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
	RemainingHeader      string
	RemainingVariable    string
	ConsumedHeader       string
	ConsumedVariable     string
	Namespace            string
	Dimensions           []LLMDimension
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
	// tokens-per-minute is what makes the node a limit rather than a comment.
	// Azure rejects the policy without it, and accepting it here would produce
	// a gateway that silently enforces nothing.
	if config.TokensPerMinute <= 0 {
		return Action{}, false, fmt.Errorf("llm-token-limit requires a positive tokens-per-minute")
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
	if config.Namespace == "" {
		config.Namespace = "llm"
	}
	return Action{Kind: ActionLLMEmitTokenMetric, LLM: config}, true, nil
}

func compileLLMConfig(item node) (LLMConfig, error) {
	config := LLMConfig{
		CounterKey:           item.Attrs["counter-key"],
		EstimatePromptTokens: strings.EqualFold(item.Attrs["estimate-prompt-tokens"], "true"),
		RetryAfterHeader:     item.Attrs["retry-after-header-name"],
		RetryAfterVariable:   item.Attrs["retry-after-variable-name"],
		RemainingHeader:      item.Attrs["remaining-tokens-header-name"],
		RemainingVariable:    item.Attrs["remaining-tokens-variable-name"],
		ConsumedHeader:       item.Attrs["tokens-consumed-header-name"],
		ConsumedVariable:     item.Attrs["tokens-consumed-variable-name"],
		Namespace:            item.Attrs["namespace"],
	}
	if raw := item.Attrs["tokens-per-minute"]; raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			return LLMConfig{}, fmt.Errorf("invalid tokens-per-minute %q", raw)
		}
		config.TokensPerMinute = value
	}
	return config, nil
}

func executeLLMTokenLimit(action Action, state *State) error {
	if state.TokenLimit == nil {
		return fmt.Errorf("llm-token-limit requires a configured token counter")
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
	remaining, retryAfter, allowed := state.TokenLimit(key, action.LLM.TokensPerMinute, estimate)
	governance := &LLMGovernance{CounterKey: key, TokensPerMinute: action.LLM.TokensPerMinute, Config: action.LLM}
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
