package policy

import (
	"errors"
	"testing"
)

// ElementPath composes what it has. A failure that knows only its section, or
// only its element, still says something rather than rendering a bare slash.
func TestPolicyErrorElementPath(t *testing.T) {
	for _, test := range []struct {
		section, element, want string
	}{
		{"inbound", "validate-jwt", "inbound/validate-jwt"},
		{"", "validate-jwt", "validate-jwt"},
		{"inbound", "", "inbound"},
		{"", "", ""},
	} {
		got := (&PolicyError{Err: errors.New("x"), section: test.section, element: test.element}).ElementPath()
		if got != test.want {
			t.Fatalf("path(%q,%q) = %q, want %q", test.section, test.element, got, test.want)
		}
	}
}

// The reason vocabulary is deliberately narrow: only expression failures are
// classified, because that is the one cause this engine can identify. Sorting
// anything else into a bucket would put a code an on-error policy might switch
// on in front of a failure Azure classifies differently.
func TestReasonIsOnlyClaimedWhereKnown(t *testing.T) {
	if got := reasonFor(errors.New("unknown member Nonexistent")); got != "ExpressionValueEvaluationFailure" {
		t.Fatalf("expression failure = %q", got)
	}
	if got := reasonFor(errors.New("member access on null")); got != "ExpressionValueEvaluationFailure" {
		t.Fatalf("null access = %q", got)
	}
	if got := reasonFor(errors.New("backend request failed")); got != "" {
		t.Fatalf("an unclassifiable failure was given the reason %q", got)
	}
	if got := reasonFor(nil); got != "" {
		t.Fatalf("nil error = %q", got)
	}
}

// locate leaves a nil error alone, and does not overwrite an inner frame's
// element with an outer one's.
func TestLocateKeepsTheInnermostFrame(t *testing.T) {
	if err := locate(nil, Action{}, &State{}); err != nil {
		t.Fatalf("nil error located = %v", err)
	}
	inner := &PolicyError{Err: errors.New("boom"), element: "validate-jwt"}
	outer := locate(inner, Action{Element: "choose", Scope: "api"}, &State{Section: "inbound"})
	var located *PolicyError
	if !errors.As(outer, &located) || located.Element() != "validate-jwt" {
		t.Fatalf("outer frame overwrote the inner element: %#v", located)
	}
	// What the inner frame could not know IS filled in.
	if located.Section() != "inbound" || located.Scope() != "api" {
		t.Fatalf("section/scope not completed: %#v", located)
	}
}

// A scope stamp reaches actions nested inside a choose branch, or a policy in a
// branch would report no scope at all.
func TestStampScopeReachesNestedActions(t *testing.T) {
	plan := Plan{Inbound: []Action{{
		Kind:     ActionChoose,
		Branches: []ChooseBranch{{Actions: []Action{{Kind: ActionSetHeader, Element: "set-header"}}}},
		Children: []Action{{Kind: ActionSetVariable, Element: "set-variable"}},
	}}}
	plan.StampScope("product")
	if plan.Inbound[0].Scope != "product" {
		t.Fatalf("top-level scope = %q", plan.Inbound[0].Scope)
	}
	if plan.Inbound[0].Branches[0].Actions[0].Scope != "product" {
		t.Fatalf("branch scope = %q", plan.Inbound[0].Branches[0].Actions[0].Scope)
	}
	if plan.Inbound[0].Children[0].Scope != "product" {
		t.Fatalf("child scope = %q", plan.Inbound[0].Children[0].Scope)
	}
	// An action that already carries a scope keeps it: composition merges
	// documents, and the one it came from is the one that matters.
	plan.StampScope("global")
	if plan.Inbound[0].Scope != "product" {
		t.Fatalf("a stamped scope was overwritten: %q", plan.Inbound[0].Scope)
	}
}

func TestErrorLocationOnlyForLocatedErrors(t *testing.T) {
	if got := errorLocation(errors.New("plain")); got != nil {
		t.Fatalf("a plain error reported a location: %#v", got)
	}
	if got := errorLocation(nil); got != nil {
		t.Fatalf("nil reported a location: %#v", got)
	}
	if got := errorLocation(&PolicyError{Err: errors.New("x"), element: "set-header"}); got == nil {
		t.Fatal("a located error reported none")
	}
}
