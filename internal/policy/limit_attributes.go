package policy

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
)

// limit_attributes.json is derived from Microsoft's vendored reference pages by
// scripts/derive_limit_attributes.py. The four limit policies differ from one
// another attribute by attribute, and transcribing that table by hand is how
// <rate-limit> came to accept counter-key, which Azure rejects. Embedding the
// derived record means the accepted surface IS the documented one, rather than
// a second copy of it that can drift.
//
//go:embed limit_attributes.json
var limitAttributesJSON []byte

type limitSurface struct {
	Commit   string                         `json:"commit"`
	Policies map[string]map[string][]string `json:"policies"`
}

var limitAttributes = parseLimitAttributes(limitAttributesJSON)

func parseLimitAttributes(raw []byte) map[string]map[string]map[string]bool {
	var derived limitSurface
	if err := json.Unmarshal(raw, &derived); err != nil {
		// Build integrity: the embedded record is generated, so a parse failure
		// is a broken build and not a runtime condition to report.
		panic(fmt.Sprintf("policy: limit_attributes.json: %v", err))
	}
	result := map[string]map[string]map[string]bool{}
	for name, sections := range derived.Policies {
		result[name] = map[string]map[string]bool{}
		for section, attributes := range sections {
			allowed := map[string]bool{}
			for _, attribute := range attributes {
				allowed[attribute] = true
			}
			result[name][section] = allowed
		}
	}
	return result
}

// limitDocumentsSection reports whether the policy documents this nested element
// at all. The by-key pair documents no elements, so <api> under one of them is
// not a limit carrying an undocumented attribute, it is not a limit at all.
func limitDocumentsSection(policy, section string) bool {
	return len(limitAttributes[policy][section]) > 0
}

// undocumentedLimitAttribute returns the first attribute this policy's section
// does not document, or "" when every one is documented. Sorted so the reported
// name is stable when a policy carries several. A section the policy documents
// no attributes for reports its first attribute, since every one of them is
// undocumented there.
func undocumentedLimitAttribute(policy, section string, attrs map[string]string) string {
	allowed := limitAttributes[policy][section]
	names := make([]string, 0, len(attrs))
	for name := range attrs {
		if !allowed[name] {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return names[0]
}
