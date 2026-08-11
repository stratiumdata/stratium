package xacml

import (
	"testing"

	"stratium/internal/policy/policytest"
)

// TestEngine_Contract runs the shared conformance suite every PolicyEngine
// must pass. It does not reimplement any of these checks itself — that is
// exactly the drift policytest.EngineContract exists to prevent.
//
// AllowAll and DenyAll each have a single unconditional Rule and no Target
// anywhere in the document: they reference the input not at all, so there
// is no fixture-side condition that could accidentally narrow them to
// "matches every input this suite happens to send" — the exact trap this
// task's own instructions name explicitly, and the one Rego's own passing
// review specifically checked for. WellFormed is a different, ordinary
// policy (a real subject-id equality match) so a mixup between it and
// AllowAll/DenyAll would not coincidentally still validate, or still carry
// the right effect. Malformed is plain invalid XML syntax — an unclosed
// tag — the same "a syntax error is a syntax error in any language"
// fixture jsonpolicy, rego, and cedar all use.
func TestEngine_Contract(t *testing.T) {
	policytest.EngineContract(t, New(), policytest.Fixtures{
		Malformed: `<Policy PolicyId="broken" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Rule RuleId="r1" Effect="Permit"`,

		WellFormed: `<Policy PolicyId="wellformed" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Target>
    <AnyOf>
      <AllOf>
        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
          <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">nobody-in-particular</AttributeValue>
          <AttributeDesignator AttributeId="subject-id" DataType="http://www.w3.org/2001/XMLSchema#string"/>
        </Match>
      </AllOf>
    </AnyOf>
  </Target>
  <Rule RuleId="wellformed-rule" Effect="Permit"/>
</Policy>`,

		AllowAll: `<Policy PolicyId="allow-all" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Rule RuleId="allow-all-rule" Effect="Permit"/>
</Policy>`,

		DenyAll: `<Policy PolicyId="deny-all" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Rule RuleId="deny-all-rule" Effect="Deny"/>
</Policy>`,
	})
}

// TestEngine_Language pins the exact string Language() returns. NewMulti
// panics on any mismatch between a Registry key and its engine's own
// Language() (see that constructor's own doc comment), and Task 6 wires
// all four engines into that Registry by key, so a silent typo here would
// surface as a startup panic far from this package rather than a local
// test failure — worth pinning directly rather than trusting
// `const language = "xacml"` to never be mistyped at its one call site.
func TestEngine_Language(t *testing.T) {
	if got := New().Language(); got != "xacml" {
		t.Fatalf(`Language() = %q, want "xacml"`, got)
	}
}
