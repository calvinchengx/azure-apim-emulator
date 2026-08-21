package policy

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// policy_sections.json is derived from Microsoft's vendored reference pages and
// published snippets by scripts/derive_policy_sections.py. Every reference page
// names the sections its policy is valid in, and Azure rejects the rest:
// <rate-limit> in <outbound> is not a limit that counts nothing, it is a policy
// document that does not deploy. The compiler had no such table, so all three of
// those documents compiled here.
//
// The table it does have is embedded rather than written out, because the
// hand-written one in the inventory was wrong for all four limit policies, which
// were the only four anyone had checked it against.
//
//go:embed policy_sections.json
var policySectionsJSON []byte

type sectionSurface struct {
	Commit   string              `json:"commit"`
	Policies map[string][]string `json:"policies"`
}

var policySections = parsePolicySections(policySectionsJSON)

func parsePolicySections(raw []byte) map[string]map[string]bool {
	var derived sectionSurface
	if err := json.Unmarshal(raw, &derived); err != nil {
		// Build integrity: the embedded record is generated, so a parse failure
		// is a broken build and not a runtime condition to report.
		panic(fmt.Sprintf("policy: policy_sections.json: %v", err))
	}
	result := map[string]map[string]bool{}
	for name, sections := range derived.Policies {
		if len(sections) == 0 {
			// A policy that is configured somewhere other than a policy section:
			// the GraphQL resolver family lives in a resolver document. There is
			// no section to hold it to.
			continue
		}
		allowed := map[string]bool{}
		for _, section := range sections {
			allowed[section] = true
		}
		result[name] = allowed
	}
	return result
}

// documentsSection reports whether this policy may appear in this section.
//
// A name the derived record does not carry documents no section, and is never
// rejected for where it appears: <base/> and the emulator's own composition
// names have no reference page, and the resolver policies have a page that names
// a resolver element instead of a section.
func documentsSection(policy, section string) bool {
	allowed, documented := policySections[policy]
	return !documented || allowed[section]
}
