package jsonpolicy

import (
	"testing"

	"stratium/internal/policy/policytest"
)

// TestEngine_Contract runs the shared conformance suite every PolicyEngine
// must pass. It does not reimplement any of these checks itself — that is
// exactly the drift policytest.EngineContract exists to prevent.
//
// AllowAll and DenyAll are the emptiest policies this schema can express: an
// empty match object, nothing else. That is deliberate, not a shortcut —
// they reference the input not at all, so there is no fixture-side
// condition that could accidentally narrow them to "matches every input
// this suite happens to send," the exact trap this task's own instructions
// name explicitly. WellFormed is a different, ordinary policy (a real
// subject constraint) so a mixup between it and AllowAll/DenyAll would not
// coincidentally still validate, or still carry the right effect. Malformed
// is plain invalid JSON syntax — a missing closing brace — the same "a
// syntax error is a syntax error in any language" fixture rego and cedar
// both use.
func TestEngine_Contract(t *testing.T) {
	policytest.EngineContract(t, New(), policytest.Fixtures{
		Malformed:  `{"effect": "allow", "match": {}`,
		WellFormed: `{"effect": "allow", "match": {"subject": {"attr": "department", "equals": "finance"}}}`,
		AllowAll:   `{"effect": "allow", "match": {}}`,
		DenyAll:    `{"effect": "deny", "match": {}}`,
	})
}
