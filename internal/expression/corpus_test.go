package expression

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The corpus gate.
//
// Every other gate in this package measures the SURFACE: which members exist,
// and what shape they answer. None of them measures the LANGUAGE. A policy is
// not a member lookup, it is an expression, and an expression this parser
// cannot read fails whatever the inventory says.
//
// So this reads Microsoft's own published policies -- 59 documents vendored at a
// pinned commit under third_party/microsoft/policy-snippets -- pulls every
// expression out of them, and parses each one. The measure is external in the
// way that matters: nobody here chose these expressions, and they are what
// Microsoft tells people to write.
//
// It is a RATCHET rather than a threshold. An expression that parses today must
// keep parsing, which no percentage floor would catch: a floor lets one
// expression regress while another improves and reports the same number.

const (
	corpusBaseline = "policy-corpus.json"
	// The commit the corpus is vendored at, recorded so the baseline says
	// which Microsoft policies it measured.
	corpusCommit = "87225c2090e45add095919e8767c37d9ece42e0c"
)

type corpusFailure struct {
	// Digest identifies the expression without carrying its whole text, so a
	// regression shows up as a new line in the baseline diff.
	Digest  string `json:"digest"`
	Reason  string `json:"reason"`
	File    string `json:"file"`
	Excerpt string `json:"excerpt"`
}

// corpusGap is one reason expressions fail, with how many fail for it. Ranked,
// so the file says where the language work actually is rather than leaving a
// reader to count 93 failures by hand.
type corpusGap struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type corpusRecord struct {
	Source   string          `json:"source"`
	Commit   string          `json:"commit"`
	Total    int             `json:"total"`
	Parsed   int             `json:"parsed"`
	Gaps     []corpusGap     `json:"gaps"`
	Failures []corpusFailure `json:"failures"`
}

// corpusEntry is one distinct expression and where it was found.
type corpusEntry struct {
	source string
	file   string
}

// corpusExpressions pulls every `@(...)` and `@{...}` out of the vendored
// policies, keyed by digest so the same expression in two documents counts once.
func corpusExpressions(t *testing.T) map[string]corpusEntry {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "..", "third_party", "microsoft", "policy-snippets", "*.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("the vendored policy corpus is missing; nothing would be measured")
	}
	found := map[string]corpusEntry{}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		// XML entities are unescaped FIRST. A policy writes `As&lt;string&gt;()`
		// and `&amp;&amp;`, so parsing the raw markup would measure the escaping
		// rather than the expression.
		for _, source := range extractExpressions(html.UnescapeString(string(raw))) {
			sum := sha256.Sum256([]byte(source))
			digest := hex.EncodeToString(sum[:])[:12]
			if _, seen := found[digest]; !seen {
				found[digest] = corpusEntry{source: source, file: filepath.Base(path)}
			}
		}
	}
	return found
}

// extractExpressions finds `@(` and `@{` and matches to the closing delimiter,
// counting nesting. A regex cannot do this: policy expressions contain their own
// parentheses and braces.
func extractExpressions(text string) []string {
	var found []string
	for i := 0; i < len(text)-1; i++ {
		if text[i] != '@' {
			continue
		}
		open := text[i+1]
		var closing byte
		switch open {
		case '(':
			closing = ')'
		case '{':
			closing = '}'
		default:
			continue
		}
		depth := 0
		for j := i + 1; j < len(text); j++ {
			if text[j] == open {
				depth++
			} else if text[j] == closing {
				depth--
				if depth == 0 {
					found = append(found, text[i:j+1])
					i = j
					break
				}
			}
		}
	}
	return found
}

func excerpt(source string) string {
	flat := strings.Join(strings.Fields(source), " ")
	if len(flat) > 80 {
		return flat[:80]
	}
	return flat
}

// reason collapses a parse error to its category, so the baseline groups by the
// gap rather than by the expression.
func reason(err error) string {
	message := err.Error()
	if index := strings.Index(message, ";"); index > 0 {
		message = message[:index]
	}
	return message
}

func measureCorpus(t *testing.T) corpusRecord {
	t.Helper()
	expressions := corpusExpressions(t)
	record := corpusRecord{
		Source: "Azure/api-management-policy-snippets, MIT",
		Commit: corpusCommit,
		Total:  len(expressions),
	}
	for digest, entry := range expressions {
		if _, _, err := Parse(entry.source); err != nil {
			record.Failures = append(record.Failures, corpusFailure{
				Digest: digest, Reason: reason(err), File: entry.file, Excerpt: excerpt(entry.source),
			})
			continue
		}
		record.Parsed++
	}
	sort.Slice(record.Failures, func(i, j int) bool {
		if record.Failures[i].Reason != record.Failures[j].Reason {
			return record.Failures[i].Reason < record.Failures[j].Reason
		}
		return record.Failures[i].Digest < record.Failures[j].Digest
	})
	counts := map[string]int{}
	for _, failure := range record.Failures {
		counts[failure.Reason]++
	}
	for reason, count := range counts {
		record.Gaps = append(record.Gaps, corpusGap{Reason: reason, Count: count})
	}
	sort.Slice(record.Gaps, func(i, j int) bool {
		if record.Gaps[i].Count != record.Gaps[j].Count {
			return record.Gaps[i].Count > record.Gaps[j].Count
		}
		return record.Gaps[i].Reason < record.Gaps[j].Reason
	})
	return record
}

func TestUpdateCorpusBaseline(t *testing.T) {
	if os.Getenv("APIM_UPDATE_CORPUS") != "1" {
		t.Skip("set APIM_UPDATE_CORPUS=1 to regenerate docs/generated/policy-corpus.json")
	}
	record := measureCorpus(t)
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "docs", "generated", corpusBaseline)
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("rewrote %s: %d of %d expressions parse", path, record.Parsed, record.Total)
}

func TestCorpusParsesWhatItParsedBefore(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "generated", corpusBaseline))
	if err != nil {
		t.Fatal(err)
	}
	var baseline corpusRecord
	if err := json.Unmarshal(raw, &baseline); err != nil {
		t.Fatal(err)
	}
	record := measureCorpus(t)

	// The corpus itself changing is a re-vendoring, which must be deliberate.
	if record.Total != baseline.Total {
		t.Fatalf("the corpus holds %d expressions, the baseline records %d; re-vendor and regenerate", record.Total, baseline.Total)
	}
	// A REGRESSION: an expression that used to parse and now does not. A parsed
	// count alone would miss this, because one expression can regress while
	// another improves and leave the number unchanged.
	was := map[string]bool{}
	for _, failure := range baseline.Failures {
		was[failure.Digest] = true
	}
	for _, failure := range record.Failures {
		if !was[failure.Digest] {
			t.Errorf("%s no longer parses (%s): %s", failure.Digest, failure.Reason, failure.Excerpt)
		}
	}
	// And the other direction: expressions that now parse are progress the
	// baseline must record, so the ratchet cannot slip back later.
	if record.Parsed > baseline.Parsed {
		t.Fatalf("%d expressions parse, up from %d; regenerate with APIM_UPDATE_CORPUS=1", record.Parsed, baseline.Parsed)
	}
	if record.Parsed < baseline.Parsed {
		t.Fatalf("%d expressions parse, down from %d", record.Parsed, baseline.Parsed)
	}
	t.Logf("corpus: %d of %d of Microsoft's own expressions parse", record.Parsed, record.Total)
}
