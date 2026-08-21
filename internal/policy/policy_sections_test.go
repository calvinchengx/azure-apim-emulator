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
// table existing at all. ErrWrongSection is what tells them apart, which is half
// of why the fault has a sentinel of its own.
func sectionRejected(document, policy, section string) bool {
	_, err := Compile(document, false)
	if !errors.Is(err, ErrWrongSection) {
		return false
	}
	// The sentinel says a policy was out of place; this says it was THIS policy,
	// so a document with two misplaced policies cannot pass for the wrong one.
	return strings.Contains(err.Error(), "<"+policy+">") && strings.Contains(err.Error(), section+":")
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
		// In BOTH modes. Strict mode governs what this emulator runs, and this
		// document is not one Azure would have deployed for it to run: deferring
		// it to execution accepts a PUT that Azure answers 400, and then fails
		// every request against the API instead of the one deploy that was wrong.
		for _, strict := range []bool{true, false} {
			if _, err := Compile(document, strict); !errors.Is(err, ErrWrongSection) {
				t.Errorf("Compile(%s, strict=%v) = %v, want ErrWrongSection", document, strict, err)
			}
		}
	}
}

// A misplaced policy and one this emulator has not implemented are different
// faults with opposite answers -- edit the document, or wait for the emulator --
// so a caller must be able to tell them apart.
func TestWrongSectionIsNotReportedAsUnsupported(t *testing.T) {
	_, err := Compile(`<policies><outbound><rate-limit calls="1" renewal-period="60"/></outbound></policies>`, true)
	if errors.Is(err, ErrUnsupported) {
		t.Errorf("a misplaced <rate-limit> was reported as unsupported: %v", err)
	}
	if !errors.Is(err, ErrWrongSection) {
		t.Fatalf("Compile() = %v, want ErrWrongSection", err)
	}
	// And the other way: <xsl-transform> is documented in <outbound> and is not
	// implemented here, which is the fault ErrUnsupported is for.
	_, err = Compile(`<policies><outbound><xsl-transform/></outbound></policies>`, true)
	if !errors.Is(err, ErrUnsupported) || errors.Is(err, ErrWrongSection) {
		t.Errorf("an unimplemented <xsl-transform> = %v, want ErrUnsupported", err)
	}
}

// The message names the section once. It used to name it twice, once in the
// wrapper compileRoot adds and once inside an `outbound/rate-limit` source, and
// that source was also a differently shaped key than every other unsupported
// element reports.
func TestWrongSectionErrorNamesTheSectionOnce(t *testing.T) {
	_, err := Compile(`<policies><outbound><rate-limit calls="1" renewal-period="60"/></outbound></policies>`, true)
	if err == nil {
		t.Fatal("Compile() = nil")
	}
	if got := strings.Count(err.Error(), "outbound"); got != 1 {
		t.Errorf("%q names outbound %d times, want 1", err.Error(), got)
	}
	if !strings.Contains(err.Error(), "<rate-limit>") {
		t.Errorf("%q does not name the policy", err.Error())
	}
}

// <base /> composes the parent scope's policies and belongs in every section.
// The section table must not reach it, or every inherited policy document stops
// compiling in three sections out of four.
func TestSectionlessConstructsAreNotRejected(t *testing.T) {
	for _, section := range []string{"inbound", "backend", "outbound", "on-error"} {
		// base is in the record with all four sections; the resolver policies are
		// in it with none, which documentsSection reads as "no section to hold it
		// to" rather than "held to nothing".
		for _, name := range []string{"base", "sql-data-source", "http-data-source"} {
			if !documentsSection(name, section) {
				t.Errorf("<%s> was held to a section it is not configured in (<%s>)", name, section)
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

// authentication-oauth2 is an emulator-only name with no reference page, so it
// follows the family it is modelled on. It was previously in the record with no
// sections at all, which left the compiler accepting it anywhere while the ledger
// published `backend` -- a section the rest of the family is not valid in either.
func TestPagelessNamesAreHeldToTheFamilyTheyFollow(t *testing.T) {
	for _, name := range []string{
		"authentication-oauth2", "authentication-basic",
		"authentication-certificate", "authentication-managed-identity",
	} {
		if !documentsSection(name, "inbound") {
			t.Errorf("<%s> is not valid in <inbound>", name)
		}
		for _, section := range []string{"backend", "outbound", "on-error"} {
			if documentsSection(name, section) {
				t.Errorf("<%s> is valid in <%s>, but the family is inbound-only", name, section)
			}
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

// A policy's own children are not in a section. <send-one-way-request> compiles
// <set-body> itself, and Microsoft's own Log_errors_to_Stackify snippet writes
// exactly that inside <on-error>, where a top-level <set-body> is not valid.
// scripts/derive_policy_sections.py reads the corpus by the same rule.
func TestAPolicysOwnChildrenAreNotHeldToTheSection(t *testing.T) {
	for _, document := range []string{
		`<policies><on-error><send-one-way-request mode="new"><set-url>http://x</set-url>` +
			`<set-method>POST</set-method><set-body>x</set-body></send-one-way-request></on-error></policies>`,
		`<policies><on-error><return-response><set-status code="503"/><set-body>x</set-body></return-response></on-error></policies>`,
	} {
		if _, err := Compile(document, true); err != nil {
			t.Errorf("Compile(%s) = %v", document, err)
		}
	}
	// The same element directly in the section, which is not valid there.
	if !sectionRejected(`<policies><on-error><set-body>x</set-body></on-error></policies>`, "set-body", "on-error") {
		t.Error("a top-level <set-body> was accepted in <on-error>")
	}
}

// A fragment's contents land in whichever section included it, so the section a
// policy is held to is the including one. A fragment is not a section of its own.
func TestIncludedFragmentsAreHeldToTheIncludingSection(t *testing.T) {
	fragments := map[string]string{"limit": `<fragment><rate-limit calls="1" renewal-period="60"/></fragment>`}
	if _, err := CompileWithFragments(
		`<policies><outbound><include-fragment fragment-id="limit"/></outbound></policies>`, fragments, true,
	); !errors.Is(err, ErrWrongSection) {
		t.Errorf("a fragment put <rate-limit> in <outbound>: %v", err)
	}
	// And in the mode a fragment is normally stored under, where the fault used
	// to be deferred to a request that named an element the document never wrote.
	if _, err := CompileWithFragments(
		`<policies><outbound><include-fragment fragment-id="limit"/></outbound></policies>`, fragments, false,
	); !errors.Is(err, ErrWrongSection) {
		t.Errorf("a fragment put <rate-limit> in <outbound> without strict mode: %v", err)
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

// InvalidPlan stands in for a document that did not compile, so the fault
// reaches the requests that use the document rather than the startup that read
// it. Dropping the plan instead would run the API as though the document had
// been empty, which reports nothing at all.
func TestInvalidPlanReportsTheCompileErrorWhereItIsUsed(t *testing.T) {
	cause := fmt.Errorf("compile policy /some/scope: outbound: <rate-limit> %w", ErrWrongSection)
	plan := InvalidPlan(cause)
	if len(plan.Inbound) != 1 {
		t.Fatalf("InvalidPlan() = %+v, want one inbound action", plan)
	}
	// Inbound alone: inbound runs first for every request, so a later section
	// could only report the same fault twice.
	if len(plan.Backend)+len(plan.Outbound)+len(plan.OnError) != 0 {
		t.Errorf("InvalidPlan() filled sections other than inbound: %+v", plan)
	}
	err := Execute(plan.Inbound, &State{})
	if !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("Execute() = %v, want ErrInvalidDocument", err)
	}
	if !strings.Contains(err.Error(), cause.Error()) {
		t.Errorf("%q does not carry the compile error it stands for", err.Error())
	}
}

// A document that composes away is not this request's problem. A child scope
// that overrides its parent without <base/> drops the parent's actions, and an
// invalid parent has to drop with them: it would not have run either way.
func TestAnInvalidPlanComposesAwayLikeAnyOther(t *testing.T) {
	plan := InvalidPlan(errors.New("compile policy /parent: broken"))
	if len(plan.Inbound) != 1 || plan.Inbound[0].Kind != ActionInvalid {
		t.Fatalf("InvalidPlan() = %+v", plan)
	}
	// Nothing here calls the gateway's composer; this states the property the
	// composer relies on, which is that the action is ordinary enough to be
	// dropped or spliced by <base/> like any other.
	if plan.Inbound[0].Kind == ActionBase {
		t.Error("an invalid plan's action must not be a <base/>")
	}
}
