package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// sectionRejected reports whether compiling this document rejected the policy
// for the section it is in, as opposed to for anything else about it. The two
// have to be told apart: nearly every probe below is a policy stripped to its
// bare element, so most of them are also invalid for want of a required
// attribute, and a test that accepted any failure would pass without the section
// table existing at all.
func sectionRejected(document, policy, section string) bool {
	compiled, err := Compile(document, false)
	if err != nil {
		return false
	}
	var walk func(actions []Action) bool
	walk = func(actions []Action) bool {
		for _, action := range actions {
			if action.Kind == ActionUnsupported && action.Source == section+"/"+policy {
				return true
			}
			if walk(action.Children) || walk(action.Otherwise) {
				return true
			}
			for _, branch := range action.Branches {
				if walk(branch.Actions) {
					return true
				}
			}
		}
		return false
	}
	return walk(compiled.Inbound) || walk(compiled.Backend) || walk(compiled.Outbound) || walk(compiled.OnError)
}

// TestPoliciesCompileOnlyInTheirDocumentedSections runs every policy in the
// derived record through all four sections. The cases come from the record, so
// they follow Microsoft's pages rather than a list maintained beside the code,
// and a policy Microsoft adds arrives already probed.
//
// The probe is the bare element, with no attributes, because the section check
// runs before the switch: a policy that is out of place is out of place whether
// or not it is otherwise well formed. That is what lets one probe cover the
// policies this emulator implements and the ones it does not alike.
func TestPoliciesCompileOnlyInTheirDocumentedSections(t *testing.T) {
	names := make([]string, 0, len(policySections))
	for name := range policySections {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) < 50 {
		t.Fatalf("derived section record holds %d policies", len(names))
	}
	for _, name := range names {
		for _, section := range []string{"inbound", "backend", "outbound", "on-error"} {
			document := fmt.Sprintf(`<policies><%s><%s/></%s></policies>`, section, name, section)
			rejected := sectionRejected(document, name, section)
			if documented := policySections[name][section]; documented && rejected {
				t.Errorf("<%s> rejected in <%s>, which its page documents", name, section)
			} else if !documented && !rejected {
				t.Errorf("<%s> accepted in <%s>, which its page does not document", name, section)
			}
		}
	}
}

// The three documents the compiler took that Azure rejects. Named here because
// they are what was reported, and because they are the case the derived record
// exists for: all three policies count requests, and counting them after the
// response has been sent counts nothing.
func TestLimitPoliciesAreRejectedOutsideInbound(t *testing.T) {
	for _, document := range []string{
		`<policies><outbound><rate-limit calls="1" renewal-period="60"/></outbound></policies>`,
		`<policies><outbound><quota calls="1" renewal-period="60"/></outbound></policies>`,
		`<policies><on-error><rate-limit-by-key calls="1" renewal-period="60" counter-key="k"/></on-error></policies>`,
	} {
		if _, err := Compile(document, true); !errors.Is(err, ErrUnsupported) {
			t.Errorf("Compile(%s) = %v, want ErrUnsupported", document, err)
		}
		// Without strict mode the document is stored and fails when execution
		// reaches it, which is how this emulator reports every other policy it
		// will not run.
		plan, err := Compile(document, false)
		if err != nil {
			t.Fatalf("Compile(%s) = %v", document, err)
		}
		actions := plan.Outbound
		if len(actions) == 0 {
			actions = plan.OnError
		}
		if err := Execute(actions, &State{}); !errors.Is(err, ErrUnsupported) {
			t.Errorf("Execute(%s) = %v, want ErrUnsupported", document, err)
		}
	}
}

// <base /> composes the parent scope's policies and belongs in every section.
// The section table must not reach it, or every inherited policy document stops
// compiling in three sections out of four.
func TestSectionlessConstructsAreNotRejected(t *testing.T) {
	for _, section := range []string{"inbound", "backend", "outbound", "on-error"} {
		for _, name := range []string{"base", "authentication-oauth2", "sql-data-source"} {
			if !documentsSection(name, section) {
				t.Errorf("<%s> was held to a section table it has no entry in (<%s>)", name, section)
			}
		}
	}
	plan, err := Compile(`<policies><inbound><base/></inbound><backend><base/></backend>`+
		`<outbound><base/></outbound><on-error><base/></on-error></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	for section, actions := range map[string][]Action{
		"inbound": plan.Inbound, "backend": plan.Backend,
		"outbound": plan.Outbound, "on-error": plan.OnError,
	} {
		if len(actions) != 1 || actions[0].Kind != ActionBase {
			t.Errorf("<base/> in <%s> compiled to %+v", section, actions)
		}
	}
}

// A policy nested in a control-flow construct is in the section that construct
// is in. Nothing else would be true of it at runtime: a <rate-limit> inside a
// <choose> in <outbound> still runs outbound.
func TestNestedPoliciesInheritTheEnclosingSection(t *testing.T) {
	for _, document := range []string{
		`<policies><outbound><choose><when condition="@(true)"><rate-limit calls="1" renewal-period="60"/></when></choose></outbound></policies>`,
		`<policies><outbound><choose><when condition="@(true)"><set-header name="X"><value>v</value></set-header></when><otherwise><rate-limit calls="1" renewal-period="60"/></otherwise></choose></outbound></policies>`,
		`<policies><outbound><retry count="1" interval="0"><rate-limit calls="1" renewal-period="60"/></retry></outbound></policies>`,
		`<policies><outbound><wait for="all"><choose><when condition="@(true)"><rate-limit calls="1" renewal-period="60"/></when></choose></wait></outbound></policies>`,
	} {
		if !sectionRejected(document, "rate-limit", "outbound") {
			t.Errorf("a nested <rate-limit> was accepted in <outbound>: %s", document)
		}
	}
	// The same policy nested the same way in the section it documents.
	if _, err := Compile(`<policies><inbound><choose><when condition="@(true)">`+
		`<rate-limit calls="1" renewal-period="60"/></when></choose></inbound></policies>`, true); err != nil {
		t.Fatalf("a nested <rate-limit> was rejected in <inbound>: %v", err)
	}
}

// A fragment's contents land in whichever section included it, so the section a
// policy is held to is the including one. A fragment is not a section of its own.
func TestIncludedFragmentsAreHeldToTheIncludingSection(t *testing.T) {
	fragments := map[string]string{"limit": `<fragment><rate-limit calls="1" renewal-period="60"/></fragment>`}
	if _, err := CompileWithFragments(
		`<policies><outbound><include-fragment fragment-id="limit"/></outbound></policies>`, fragments, true,
	); !errors.Is(err, ErrUnsupported) {
		t.Errorf("a fragment put <rate-limit> in <outbound>: %v", err)
	}
	if _, err := CompileWithFragments(
		`<policies><inbound><include-fragment fragment-id="limit"/></inbound></policies>`, fragments, true,
	); err != nil {
		t.Errorf("a fragment's <rate-limit> was rejected in <inbound>: %v", err)
	}
}

// An unknown section is reported as one. Its children are all in a section no
// page documents, so compiling them first would report one of those instead and
// bury the fault.
func TestUnknownSectionIsReportedBeforeItsChildren(t *testing.T) {
	_, err := Compile(`<policies><in-bound><set-header name="X"><value>v</value></set-header></in-bound></policies>`, true)
	if err == nil || !strings.Contains(err.Error(), "unknown policy section <in-bound>") {
		t.Fatalf("Compile() = %v", err)
	}
}

// An unreadable record is a broken build, not an empty one: degrading quietly
// would restore exactly the leniency it was derived to remove.
func TestUnreadableSectionSurfacePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a corrupt policy_sections.json was accepted")
		}
	}()
	parsePolicySections([]byte("not json"))
}
