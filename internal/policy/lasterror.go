package policy

import (
	"errors"
	"strings"

	expr "github.com/calvinchengx/azure-apim-emulator/internal/expression"
)

// Where a policy failure happened.
//
// `context.LastError` is not just a message: an on-error policy routes on WHICH
// element failed, in which section, in which scope. Carrying only the text --
// which is all this engine did -- means an on-error handler can log the failure
// and cannot act on it.

// PolicyError is a failure with the location that produced it.
type PolicyError struct {
	// Err is the failure itself. Wrapped rather than replaced so errors.Is and
	// errors.As keep working for callers that already inspect it.
	Err error
	// Element is the policy element that failed, and Source repeats it because
	// Azure exposes both names for the same thing.
	element string
	section string
	scope   string
	// reason is Azure's short classification. It is populated ONLY where this
	// engine genuinely knows one; Azure's full reason vocabulary is not
	// reproduced, and inventing codes an on-error policy might switch on would
	// be worse than leaving it empty.
	reason string
}

func (e *PolicyError) Error() string { return e.Err.Error() }

// The accessors satisfy expression.ErrorLocation, which is how the binder reads
// a failure's position without this package and that one importing each other.
func (e *PolicyError) Element() string { return e.element }
func (e *PolicyError) Section() string { return e.section }
func (e *PolicyError) Scope() string   { return e.scope }
func (e *PolicyError) Reason() string  { return e.reason }
func (e *PolicyError) Unwrap() error   { return e.Err }

// ElementPath is where the element sits, as `section/element`.
//
// Azure reports a deeper path for a nested element; this reports the section
// and the element that failed, which is what an on-error policy switches on.
// The nesting is a known simplification, stated in `docs/parity.md` rather than
// faked with a path this engine cannot compute.
func (e *PolicyError) ElementPath() string {
	switch {
	case e.section == "" && e.element == "":
		return ""
	case e.section == "":
		return e.element
	case e.element == "":
		return e.section
	default:
		return e.section + "/" + e.element
	}
}

// reasonFor classifies a failure where the engine genuinely can.
//
// Only expression evaluation is classified, because that is the one failure
// this engine raises from a single identifiable cause. Everything else keeps an
// empty reason rather than being sorted into a bucket that might not be Azure's.
func reasonFor(err error) string {
	if err == nil {
		return ""
	}
	if strings.Contains(err.Error(), "unknown member") ||
		strings.Contains(err.Error(), "member access on null") ||
		strings.Contains(err.Error(), "unknown identifier") {
		return "ExpressionValueEvaluationFailure"
	}
	return ""
}

// locate attaches the failing action's location to an error.
//
// An error already carrying a location keeps it: the innermost failure is the
// specific one, and a parent overwriting it would report `choose` failing
// wherever a branch's own element did.
func locate(err error, action Action, state *State) error {
	if err == nil {
		return nil
	}
	var located *PolicyError
	if errors.As(err, &located) {
		// Fill in only what the inner frame could not know.
		if located.section == "" {
			located.section = state.Section
		}
		if located.scope == "" {
			located.scope = action.Scope
		}
		return err
	}
	return &PolicyError{
		Err: err, element: action.Element, section: state.Section,
		scope: action.Scope, reason: reasonFor(err),
	}
}

// StampScope records which policy document a plan's actions came from.
//
// Applied when each document is compiled, so the scope survives the composition
// that merges service, product, API and operation policies into one plan. A
// scope derived after composition could only guess.
func (p *Plan) StampScope(scope string) {
	for _, section := range [][]Action{p.Inbound, p.Backend, p.Outbound, p.OnError} {
		stampScope(section, scope)
	}
}

func stampScope(actions []Action, scope string) {
	for index := range actions {
		if actions[index].Scope == "" {
			actions[index].Scope = scope
		}
		stampScope(actions[index].Children, scope)
		for branch := range actions[index].Branches {
			stampScope(actions[index].Branches[branch].Actions, scope)
		}
	}
}

// ScopeOf classifies a policy scope id the way Azure names it.
func ScopeOf(scopeID string) string {
	lower := strings.ToLower(scopeID)
	switch {
	case strings.Contains(lower, "/operations/"):
		return "operation"
	case strings.Contains(lower, "/products/"):
		return "product"
	case strings.Contains(lower, "/apis/"):
		return "api"
	default:
		// A service-scoped policy is what Azure calls global: it applies to
		// everything the service serves.
		return "global"
	}
}

// errorLocation exposes a failure's position to the expression binder, and nil
// for an error that carries none.
func errorLocation(err error) expr.ErrorLocation {
	var located *PolicyError
	if err != nil && errors.As(err, &located) {
		return located
	}
	return nil
}
