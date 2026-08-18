package expression

import (
	"slices"
	"testing"
)

// The surface is derived from two vendored sources, and the point of carrying
// both is that they disagree. A member only one source names is a weaker claim
// than one both carry, and the ledger records which.
func TestDocumentedSourcesAreRecorded(t *testing.T) {
	// The reference documents this one and the toolkit does not.
	if sources, ok := DocumentedSources("context", "Backend"); !ok || !slices.Contains(sources, "reference") {
		t.Fatalf("context.Backend sources = %v, %v", sources, ok)
	}
	// And the other direction: the toolkit's `context` carries Trace, which the
	// reference's own context row omits.
	if sources, ok := DocumentedSources("context", "Trace"); !ok || !slices.Contains(sources, "toolkit") {
		t.Fatalf("context.Trace sources = %v, %v", sources, ok)
	}
	// A member nobody documents is reported as undocumented rather than as
	// documented by nobody, which would read as an empty source list.
	if sources, ok := DocumentedSources("LastError", "ElementPath"); ok {
		t.Fatalf("LastError.ElementPath is not documented, but reported %v", sources)
	}
}

// A framework entry claims a .NET type Microsoft lists. A type this emulator
// does not map is refused rather than defaulting to something plausible.
func TestFrameworkTypeMapping(t *testing.T) {
	if dotted, ok := frameworkTypeOf("Certificate"); !ok || dotted == "" {
		t.Fatalf("Certificate maps to %q, %v", dotted, ok)
	}
	if _, ok := frameworkTypeOf("Nonexistent"); ok {
		t.Fatal("an unmapped type claimed a .NET type")
	}
}

// An unreadable surface is a broken build, not an empty surface: degrading
// quietly would make the inventory report that Microsoft documents nothing.
func TestUnreadableSurfacePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a corrupt documented.json was accepted")
		}
	}()
	parseDocumented([]byte("not json"))
}
