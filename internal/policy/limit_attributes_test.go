package policy

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// limitProbeValues gives each documented attribute a value that is plausible for
// it. Every documented attribute must appear here: a missing one fails the test
// rather than being skipped, so an attribute Microsoft adds cannot slip through
// as a silently unprobed name.
var limitProbeValues = map[string]string{
	"bandwidth":                     "8",
	"calls":                         "1",
	"counter-key":                   "k",
	"first-period-start":            "2024-01-01T00:00:00Z",
	"id":                            "demo-id",
	"increment-condition":           "@(true)",
	"increment-count":               "1",
	"name":                          "demo",
	"remaining-calls-header-name":   "X-Remaining",
	"remaining-calls-variable-name": "remaining",
	"renewal-period":                "60",
	"retry-after-header-name":       "X-Retry",
	"retry-after-variable-name":     "retryAfter",
	"total-calls-header-name":       "X-Total",
}

// limitProbeOverrides hold values that are only valid for one policy. The
// families bound renewal-period in opposite directions: the rate-limit pair caps
// a sliding window at 300 seconds, quota-by-key requires at least that.
var limitProbeOverrides = map[string]map[string]string{
	"quota-by-key": {"renewal-period": "300"},
}

func limitProbeValue(policy, attribute string) string {
	if value, overridden := limitProbeOverrides[policy][attribute]; overridden {
		return value
	}
	return limitProbeValues[attribute]
}

// limitBaselines are the minimum each policy needs to compile, before a probe
// attribute is added.
var limitBaselines = map[string]string{
	"rate-limit":        `calls="1" renewal-period="60"`,
	"quota":             `calls="1" renewal-period="60"`,
	"rate-limit-by-key": `calls="1" renewal-period="60" counter-key="k"`,
	"quota-by-key":      `calls="1" renewal-period="300" counter-key="k"`,
}

func planRejects(t *testing.T, document string) bool {
	t.Helper()
	compiled, err := Compile(document, false)
	if err != nil {
		return true
	}
	var walk func(actions []Action) bool
	walk = func(actions []Action) bool {
		for _, action := range actions {
			if action.Kind == ActionUnsupported || walk(action.Children) {
				return true
			}
		}
		return false
	}
	return walk(compiled.Inbound)
}

// TestLimitPoliciesAcceptExactlyTheDocumentedAttributes checks the compiler
// against Microsoft's own attribute tables in both directions: a documented
// attribute must compile, and an attribute documented for a SIBLING limit policy
// but not this one must not.
//
// The sibling set is what makes this worth running. The four policies look
// interchangeable and are not: bandwidth is on the quota pair only, counter-key
// and increment-* on the by-key pair, and the response and variable attributes
// on the rate-limit pair. Every case here comes from the derived record, so the
// probes follow the reference rather than a list maintained beside the code.
//
// It checks which attributes are ACCEPTED, not which are honoured. An attribute
// the compiler takes and ignores passes this test; the behaviour tests in
// policy_test.go are what cover honouring.
func TestLimitPoliciesAcceptExactlyTheDocumentedAttributes(t *testing.T) {
	universe := map[string]map[string]bool{}
	for name := range limitBaselines {
		for _, section := range []string{"attributes", "api", "operation"} {
			for _, attribute := range limitAttributeNames(name, section) {
				if _, known := limitProbeValues[attribute]; !known {
					t.Fatalf("%s/%s documents %q with no probe value", name, section, attribute)
				}
				if universe[section] == nil {
					universe[section] = map[string]bool{}
				}
				universe[section][attribute] = true
			}
		}
	}
	if len(universe["attributes"]) == 0 || len(universe["api"]) == 0 {
		t.Fatalf("derived surface is empty: %v", universe)
	}

	document := func(name, section, attribute string) string {
		probe := ""
		if attribute != "" {
			probe = fmt.Sprintf(` %s=%q`, attribute, limitProbeValue(name, attribute))
		}
		switch section {
		case "attributes":
			return fmt.Sprintf(`<policies><inbound><%s %s%s/></inbound></policies>`, name, limitBaselines[name], probe)
		case "api":
			return fmt.Sprintf(`<policies><inbound><%s %s><api name="demo" calls="1"%s/></%s></inbound></policies>`, name, limitBaselines[name], probe, name)
		default:
			return fmt.Sprintf(`<policies><inbound><%s %s><api name="demo" calls="1"><operation name="get" calls="1"%s/></api></%s></inbound></policies>`, name, limitBaselines[name], probe, name)
		}
	}

	for _, name := range sortedKeys(limitBaselines) {
		for _, section := range []string{"attributes", "api", "operation"} {
			documented := limitAttributeNames(name, section)
			if len(documented) == 0 {
				if section == "attributes" {
					t.Fatalf("%s documents no attributes", name)
				}
				// The by-key pages have no Elements section at all, so a nested
				// <api> or <operation> is not a documented element with unknown
				// attributes, it is not accepted there in any form.
				if !strings.HasSuffix(name, "-by-key") {
					t.Fatalf("%s documents no %s attributes", name, section)
				}
				if !planRejects(t, document(name, section, "")) {
					t.Errorf("%s accepts a nested <%s>, which its page does not document", name, section)
				}
				continue
			}
			allowed := map[string]bool{}
			for _, attribute := range documented {
				allowed[attribute] = true
				if planRejects(t, document(name, section, attribute)) {
					t.Errorf("%s rejects its own documented %s attribute %q", name, section, attribute)
				}
			}
			for _, attribute := range sortedSet(universe[section]) {
				if allowed[attribute] {
					continue
				}
				if !planRejects(t, document(name, section, attribute)) {
					t.Errorf("%s accepts %q, which its %s table does not document", name, attribute, section)
				}
			}
		}
	}
}

func sortedKeys(source map[string]string) []string {
	keys := make([]string, 0, len(source))
	for key := range source {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedSet(source map[string]bool) []string {
	keys := make([]string, 0, len(source))
	for key := range source {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// limitAttributeNames lists one section's documented attributes. Tests read it
// so the cases they probe come from Microsoft's table rather than from a list
// beside the code under test.
func limitAttributeNames(policy, section string) []string {
	names := make([]string, 0, len(limitAttributes[policy][section]))
	for name := range limitAttributes[policy][section] {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// An unreadable surface is a broken build, not an empty one: degrading quietly
// would make the compiler accept every attribute on every limit policy, which
// is exactly the leniency the derived record exists to remove.
func TestUnreadableLimitSurfacePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a corrupt limit_attributes.json was accepted")
		}
	}()
	parseLimitAttributes([]byte("not json"))
}
