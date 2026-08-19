package expression

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// The evaluation gate.
//
// The corpus gate measures whether an expression PARSES. That is not whether it
// works: `Url.Query` parsed for months while returning the wrong shape, and
// binding `Split` moved twelve expressions from failing to working while the
// parse number sat unchanged. Twice now, a real capability change has been
// invisible to every check running.
//
// So this evaluates every expression the corpus gate parsed, against a fixed
// fixture, and ratchets on the result the same way.
//
// WHAT IT DOES NOT MEASURE, stated because the number would otherwise be read
// as more than it is: an expression is counted when it evaluates WITHOUT ERROR,
// not when it produces the right answer, and it runs against ONE fixture. An
// expression needing a variable this fixture does not set fails here for a
// reason that is about the fixture rather than about the emulator. It is still
// a ratchet -- a member that stops resolving surfaces immediately -- and the
// blockers it names have so far been real.

const evaluationBaseline = "policy-evaluation.json"

type evaluationBlocker struct {
	Digest  string `json:"digest"`
	Reason  string `json:"reason"`
	Excerpt string `json:"excerpt"`
}

type evaluationGap struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type evaluationRecord struct {
	Note      string              `json:"note"`
	Parsed    int                 `json:"parsed"`
	Evaluated int                 `json:"evaluated"`
	Gaps      []evaluationGap     `json:"gaps"`
	Blockers  []evaluationBlocker `json:"blockers"`
}

// evaluationFixture is the context every corpus expression is evaluated
// against. It is deliberately ORDINARY -- one request, one response, a few
// identity facts -- rather than tuned to make expressions pass: a fixture built
// to raise the number would measure the fixture.
//
// It must also be DETERMINISTIC, so a run today and a run tomorrow agree. The
// timestamp and elapsed time are fixed for that reason.
func evaluationFixture() *Env {
	request := httptest.NewRequest(http.MethodPost, "https://api.example/orders/A-1?id=A-1", strings.NewReader(`{"a":1}`))
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Cookie", "a=1;b=2")
	return Bind(Context{
		Request:           request,
		Response:          &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}},
		Variables:         map[string]string{"v": "x"},
		LastError:         errors.New("something failed"),
		Api:               &ApiContext{Id: "orders", Name: "Orders", Path: "orders", ServiceUrl: "https://backend.test"},
		Operation:         &OperationContext{Id: "get", Name: "Get", Method: http.MethodGet, UrlTemplate: "/{id}"},
		Product:           &ProductContext{Id: "starter", Name: "Starter"},
		Subscription:      &SubscriptionContext{Id: "sub", Name: "Sub"},
		User:              &UserContext{Id: "ada", Email: "ada@example.test"},
		Deployment:        &DeploymentContext{ServiceName: "emulator", Region: "local", Gateway: &GatewayContext{Id: "managed"}},
		Backend:           &BackendContext{Id: "primary", Type: "Single"},
		Timestamp:         time.Unix(0, 0).UTC(),
		Elapsed:           func() time.Duration { return 0 },
		RequestId:         "req-1",
		OriginalUrl:       "https://api.example/orders/A-1?id=A-1",
		MatchedParameters: map[string]string{"id": "A-1"},
		Certificates:      map[string]*x509.Certificate{},
	})
}

// evaluationReason collapses a failure to its category, so the baseline groups
// by the gap rather than by the expression.
func evaluationReason(err error) string {
	message := err.Error()
	switch {
	case strings.Contains(message, "unbound identifier"):
		fields := strings.Fields(message)
		return "unbound identifier " + fields[len(fields)-1]
	case strings.Contains(message, "unknown member "):
		at := strings.Index(message, "unknown member ")
		return "unknown member " + strings.Fields(message[at+len("unknown member "):])[0]
	}
	if len(message) > 60 {
		message = message[:60]
	}
	return message
}

func measureEvaluation(t *testing.T) evaluationRecord {
	t.Helper()
	env := evaluationFixture()
	record := evaluationRecord{
		Note: "Corpus expressions that EVALUATE, not merely parse. See policy-corpus.json for the parse measure.",
	}
	for digest, entry := range corpusExpressions(t) {
		expr, _, err := Parse(entry.source)
		if err != nil {
			continue
		}
		record.Parsed++
		if _, err := expr.eval(env); err != nil {
			record.Blockers = append(record.Blockers, evaluationBlocker{
				Digest: digest, Reason: evaluationReason(err), Excerpt: excerpt(entry.source),
			})
			continue
		}
		record.Evaluated++
	}
	sort.Slice(record.Blockers, func(i, j int) bool {
		if record.Blockers[i].Reason != record.Blockers[j].Reason {
			return record.Blockers[i].Reason < record.Blockers[j].Reason
		}
		return record.Blockers[i].Digest < record.Blockers[j].Digest
	})
	counts := map[string]int{}
	for _, blocker := range record.Blockers {
		counts[blocker.Reason]++
	}
	for reason, count := range counts {
		record.Gaps = append(record.Gaps, evaluationGap{Reason: reason, Count: count})
	}
	sort.Slice(record.Gaps, func(i, j int) bool {
		if record.Gaps[i].Count != record.Gaps[j].Count {
			return record.Gaps[i].Count > record.Gaps[j].Count
		}
		return record.Gaps[i].Reason < record.Gaps[j].Reason
	})
	return record
}

func TestUpdateEvaluationBaseline(t *testing.T) {
	if os.Getenv("APIM_UPDATE_EVALUATION") != "1" {
		t.Skip("set APIM_UPDATE_EVALUATION=1 to regenerate docs/generated/policy-evaluation.json")
	}
	record := measureEvaluation(t)
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "docs", "generated", evaluationBaseline)
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("rewrote %s: %d of %d parsed expressions evaluate", path, record.Evaluated, record.Parsed)
}

func TestCorpusEvaluatesWhatItEvaluatedBefore(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "generated", evaluationBaseline))
	if err != nil {
		t.Fatal(err)
	}
	var baseline evaluationRecord
	if err := json.Unmarshal(raw, &baseline); err != nil {
		t.Fatal(err)
	}
	record := measureEvaluation(t)

	// A REGRESSION: an expression that used to evaluate and now does not. The
	// count alone would miss it, because one can break while another is fixed.
	was := map[string]bool{}
	for _, blocker := range baseline.Blockers {
		was[blocker.Digest] = true
	}
	for _, blocker := range record.Blockers {
		if !was[blocker.Digest] {
			t.Errorf("%s no longer evaluates (%s): %s", blocker.Digest, blocker.Reason, blocker.Excerpt)
		}
	}
	if record.Evaluated > baseline.Evaluated {
		t.Fatalf("%d expressions evaluate, up from %d; regenerate with APIM_UPDATE_EVALUATION=1", record.Evaluated, baseline.Evaluated)
	}
	if record.Evaluated < baseline.Evaluated {
		t.Fatalf("%d expressions evaluate, down from %d", record.Evaluated, baseline.Evaluated)
	}
	// The fixture must keep reaching most of the corpus. A change that broke it
	// would otherwise report a tidy zero blockers over nothing at all.
	if record.Parsed < 250 {
		t.Fatalf("only %d expressions parsed; the evaluation gate is measuring almost nothing", record.Parsed)
	}
	t.Logf("evaluation: %d of %d parsed corpus expressions evaluate", record.Evaluated, record.Parsed)
}
