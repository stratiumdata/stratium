package rego

import (
	"testing"

	"stratium/internal/policy/policytest"
)

// TestEngine_Contract runs the shared conformance suite every PolicyEngine
// must pass. It does not reimplement any of these checks itself — that is
// exactly the drift policytest.EngineContract exists to prevent. Malformed
// deliberately reuses the unbalanced-bracket shape cedar's fixture uses (a
// syntax error is a syntax error in any language); WellFormed, AllowAll, and
// DenyAll are otherwise unrelated policies so a mixup between them would not
// coincidentally still compile or still carry the right effect.
func TestEngine_Contract(t *testing.T) {
	policytest.EngineContract(t, New(), policytest.Fixtures{
		Malformed: `package stratium.policy

allow if { unbalanced [[`,
		WellFormed: `package stratium.policy

allow if {
	input.principal.subject == "nobody-in-particular"
}`,
		AllowAll: `package stratium.policy

allow := true`,
		DenyAll: `package stratium.policy

deny := true`,
	})
}
