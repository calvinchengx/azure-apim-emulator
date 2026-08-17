package llm

import "testing"

func TestUsageFromBody(t *testing.T) {
	usage, ok := UsageFromBody([]byte(`{"choices":[],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}`))
	if !ok || usage.PromptTokens != 11 || usage.CompletionTokens != 7 || usage.Total() != 18 {
		t.Fatalf("usage = %#v, %v", usage, ok)
	}
	// A provider reporting parts but no total is not assumed to be
	// arithmetically consistent with itself; the parts are summed only then.
	partial, ok := UsageFromBody([]byte(`{"usage":{"prompt_tokens":3,"completion_tokens":4}}`))
	if !ok || partial.Total() != 7 {
		t.Fatalf("partial usage total = %d", partial.Total())
	}
	if _, ok := UsageFromBody([]byte(`{"choices":[]}`)); ok {
		t.Fatal("a body with no usage object reported usage")
	}
	if _, ok := UsageFromBody([]byte(`not json`)); ok {
		t.Fatal("unparsable body reported usage")
	}
	if !(Usage{}).Empty() || (Usage{PromptTokens: 1}).Empty() {
		t.Fatal("Empty is wrong")
	}
}

// Usage arrives on ONE chunk near the end and only when the caller asked for
// it. Reading the first parsable chunk would report zero for every stream.
func TestUsageFromStream(t *testing.T) {
	stream := "data: {\"choices\":[{\"delta\":{\"content\":\"He\"}}],\"usage\":null}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"content\":\"llo\"}}],\"usage\":null}\n\n" +
		"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":2,\"total_tokens\":11}}\n\n" +
		"data: [DONE]\n\n"
	usage, ok := UsageFromStream([]byte(stream))
	if !ok || usage.Total() != 11 {
		t.Fatalf("stream usage = %#v, %v", usage, ok)
	}
	// A caller that did not pass stream_options.include_usage gets no usage at
	// all. That is a real and common case, not an error.
	without := "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n"
	if _, ok := UsageFromStream([]byte(without)); ok {
		t.Fatal("a stream without usage reported usage")
	}
	noise := ": keep-alive\n\nevent: ping\n\ndata:\n\ndata: not json\n\n"
	if _, ok := UsageFromStream([]byte(noise)); ok {
		t.Fatal("stream noise reported usage")
	}
}

func TestStreamCounterPassesBytesThrough(t *testing.T) {
	stream := "data: {\"usage\":{\"total_tokens\":5}}\n\ndata: [DONE]\n\n"
	counter := NewStreamCounter(&chunkReader{data: []byte(stream), size: 7})
	got := make([]byte, 0, len(stream))
	buffer := make([]byte, 4)
	for {
		read, err := counter.Read(buffer)
		got = append(got, buffer[:read]...)
		if err != nil {
			break
		}
	}
	// The bytes the caller receives must be exactly the bytes the model sent:
	// counting happens on the way past, it does not rewrite the stream.
	if string(got) != stream {
		t.Fatalf("stream was altered: %q", string(got))
	}
	if usage, ok := counter.Usage(); !ok || usage.Total() != 5 {
		t.Fatalf("counter usage = %#v, %v", usage, ok)
	}
}

// chunkReader hands out small reads, the way a network body does.
type chunkReader struct {
	data []byte
	size int
	at   int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.at >= len(r.data) {
		return 0, errDone
	}
	end := r.at + r.size
	if end > len(r.data) {
		end = len(r.data)
	}
	read := copy(p, r.data[r.at:end])
	r.at += read
	return read, nil
}

var errDone = &doneError{}

type doneError struct{}

func (*doneError) Error() string { return "EOF" }

func TestEstimateIsAnApproximation(t *testing.T) {
	// The contract asserted here is ORDERING and non-zero-ness, deliberately
	// not exact counts: this is an approximation, and a test pinning it to
	// specific numbers would dress it up as a tokenizer.
	short := Estimate([]byte(`{"messages":[{"role":"user","content":"hi"}]}`))
	long := Estimate([]byte(`{"messages":[{"role":"user","content":"the quick brown fox jumps over the lazy dog again and again"}]}`))
	if short <= 0 || long <= short {
		t.Fatalf("estimate ordering: short=%d long=%d", short, long)
	}
	parts := Estimate([]byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hello there"},{"type":"image_url","image_url":{"url":"https://x/y.png"}}]}]}`))
	if parts <= 0 {
		t.Fatalf("content parts estimate = %d", parts)
	}
	if Estimate([]byte(`{"prompt":"complete this"}`)) <= 0 {
		t.Fatal("legacy prompt field was not counted")
	}
	if Estimate([]byte(`{"input":"embed this"}`)) <= 0 {
		t.Fatal("embeddings input was not counted")
	}
	// Anything unparsable still yields a number: the caller has to decide
	// something, and refusing would fail a request the model would have served.
	if Estimate([]byte(`not json at all`)) <= 0 {
		t.Fatal("unparsable body estimated zero")
	}
	// Punctuation-only content splits into no words at all, which must be zero
	// rather than a division by nothing.
	if got := Estimate([]byte(`{"prompt":"!!! ... ???"}`)); got != 0 {
		t.Fatalf("punctuation-only prompt estimated %d", got)
	}
	if Estimate([]byte(`{"messages":[]}`)) != 0 {
		t.Fatalf("an empty request estimated non-zero")
	}
	if Estimate([]byte(`{"messages":[{"role":"user","content":42}]}`)) <= 0 {
		t.Fatal("a non-textual content estimated zero overall")
	}
}

func TestIsEventStream(t *testing.T) {
	if !IsEventStream("text/event-stream; charset=utf-8") || !IsEventStream(" TEXT/EVENT-STREAM") {
		t.Fatal("event stream not recognised")
	}
	if IsEventStream("application/json") || IsEventStream("") {
		t.Fatal("non-stream recognised as event stream")
	}
}
