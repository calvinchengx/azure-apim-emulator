// Package llm reads the token accounting that model APIs report about
// themselves, and estimates it where a decision has to be made before the model
// has answered.
//
// The distinction between those two is the whole design, and it is graded
// rather than blended. Numbers taken from a model's own `usage` object are
// EXACT: they are the provider's own count, and the emulator only has to find
// them. Numbers produced by Estimate are an APPROXIMATION and will not agree
// with Azure, which counts with the model's real tokenizer (cl100k_base,
// o200k_base). Shipping an invented tokenizer as though it were the real one
// would be the failure this family keeps finding: plausible output, no local
// symptom, disagreement only against a real deployment.
package llm

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode"
)

// Usage is what a model API reports it spent.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// Total is the token count to charge, preferring the provider's own total.
//
// A provider that reports parts but not a total is not assumed to be
// arithmetically consistent with itself; the parts are summed only when the
// total is absent.
func (u Usage) Total() int {
	if u.TotalTokens > 0 {
		return u.TotalTokens
	}
	return u.PromptTokens + u.CompletionTokens
}

// Empty reports whether nothing was accounted.
func (u Usage) Empty() bool { return u.PromptTokens == 0 && u.CompletionTokens == 0 && u.TotalTokens == 0 }

type usageEnvelope struct {
	Usage *Usage `json:"usage"`
}

// UsageFromBody reads the `usage` object from a non-streamed completion.
func UsageFromBody(body []byte) (Usage, bool) {
	var envelope usageEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil || envelope.Usage == nil {
		return Usage{}, false
	}
	return *envelope.Usage, true
}

// UsageFromStream reads the `usage` object out of a server-sent-event stream.
//
// OpenAI-compatible streams carry usage on ONE chunk near the end, and only
// when the caller asked for it with `stream_options: {include_usage: true}`;
// every other chunk carries `usage: null`. So this scans to the end rather than
// stopping at the first parsable chunk, and reports false when the caller never
// asked -- which is a real and common case, not an error.
func UsageFromStream(stream []byte) (Usage, bool) {
	var found Usage
	var ok bool
	scanner := bufio.NewScanner(bytes.NewReader(stream))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		payload, isData := strings.CutPrefix(line, "data:")
		if !isData {
			continue
		}
		payload = strings.TrimSpace(payload)
		if payload == "" || payload == "[DONE]" {
			continue
		}
		if usage, has := UsageFromBody([]byte(payload)); has {
			found, ok = usage, true
		}
	}
	return found, ok
}

// StreamCounter tees a streamed response so its token accounting can be read
// once the stream ends.
//
// A streamed body cannot be inspected by an outbound policy: it is written to
// the caller as it arrives, and buffering it to look would destroy the
// streaming the caller asked for. So the counting happens on the way past.
type StreamCounter struct {
	source io.Reader
	buffer bytes.Buffer
}

// NewStreamCounter wraps a response body.
func NewStreamCounter(source io.Reader) *StreamCounter { return &StreamCounter{source: source} }

// Read passes bytes through untouched, retaining a copy for accounting.
func (c *StreamCounter) Read(p []byte) (int, error) {
	read, err := c.source.Read(p)
	if read > 0 {
		c.buffer.Write(p[:read])
	}
	return read, err
}

// Usage reports what the finished stream accounted for.
func (c *StreamCounter) Usage() (Usage, bool) { return UsageFromStream(c.buffer.Bytes()) }

// Estimate approximates the prompt tokens in a chat-completion request body.
//
// APPROXIMATION, AND DELIBERATELY A CRUDE ONE. Azure runs the model's real
// tokenizer here; this counts whitespace-and-punctuation-separated words and
// applies the ratio OpenAI publishes as a rule of thumb, roughly four
// characters per token for English. It will disagree with Azure on any specific
// request, and it is used only where a limit decision must be made BEFORE the
// model has answered -- `estimate-prompt-tokens="true"`. With that attribute
// false, nothing here runs and every number comes from the provider.
//
// A more elaborate estimator would be worse, not better: it would narrow the
// gap enough to look authoritative while still being wrong.
func Estimate(body []byte) int {
	var request struct {
		Messages []struct {
			Content any `json:"content"`
		} `json:"messages"`
		Prompt any `json:"prompt"`
		Input  any `json:"input"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		return estimateText(string(body))
	}
	total := 0
	for _, message := range request.Messages {
		total += estimateContent(message.Content)
		// Every message carries a few tokens of role and delimiter framing.
		// OpenAI documents this overhead as about 4 tokens per message.
		total += 4
	}
	total += estimateContent(request.Prompt)
	total += estimateContent(request.Input)
	// No fallback for a body that PARSED but carried none of these fields. It
	// genuinely has no prompt to charge for, and estimating the raw JSON text
	// instead would bill a caller for the shape of its own request.
	return total
}

// estimateContent handles the several shapes a message body may take: a plain
// string, an array of content parts, or a nested object.
func estimateContent(value any) int {
	switch typed := value.(type) {
	case nil:
		return 0
	case string:
		return estimateText(typed)
	case []any:
		total := 0
		for _, item := range typed {
			total += estimateContent(item)
		}
		return total
	case map[string]any:
		total := 0
		for key, item := range typed {
			// Only textual parts are counted. An image part's token cost
			// depends on its dimensions, which this cannot know, and guessing
			// would be worse than declining.
			if key == "text" || key == "content" {
				total += estimateContent(item)
			}
		}
		return total
	default:
		return 0
	}
}

func estimateText(text string) int {
	words := strings.FieldsFunc(text, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsPunct(r)
	})
	if len(words) == 0 {
		return 0
	}
	// Roughly 4 characters per token, with every word costing at least one.
	total := 0
	for _, word := range words {
		total += (len(word) + 3) / 4
	}
	return total
}

// IsEventStream reports whether a content type is a server-sent-event stream.
func IsEventStream(contentType string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(contentType)), "text/event-stream")
}
