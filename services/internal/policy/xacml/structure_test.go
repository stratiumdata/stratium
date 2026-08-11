package xacml

import (
	"context"
	"strings"
	"testing"
)

// wrapPolicy builds a minimal, otherwise-valid <Policy> document with body
// substituted in as the Rule content — the shared shell every
// unsupported-construct test below mutates in exactly one place, so each
// test failure is attributable to the one construct it names rather than
// to some other incidental difference between fixtures.
func wrapPolicy(body string) string {
	return `<Policy PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Rule RuleId="r1" Effect="Permit">` + body + `</Rule>
</Policy>`
}

// TestValidate_RejectsEachUnsupportedConstructByName is this task's central
// required property: full XACML 3.0 is out of scope, and every construct
// outside the supported subset must be rejected by Validate with that
// construct's own name in the error — never silently accepted and ignored.
// Each case below is a real XACML 3.0 element this engine deliberately does
// not implement; every one of them is also individually a way a document
// could otherwise be accepted while its author's actual intent (a
// condition, an obligation, a referenced sub-policy) never takes effect —
// see the task report for the full enumeration of this failure class.
func TestValidate_RejectsEachUnsupportedConstructByName(t *testing.T) {
	cases := []struct {
		name string
		text string
		// wantNamed is the construct's own element/attribute name, which
		// must appear verbatim in the rejection so an author can find it.
		wantNamed string
	}{
		{
			name:      "Condition inside a Rule",
			text:      wrapPolicy(`<Condition></Condition>`),
			wantNamed: "Condition",
		},
		{
			name: "ObligationExpressions on a Policy",
			text: `<Policy PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Rule RuleId="r1" Effect="Permit"/>
  <ObligationExpressions></ObligationExpressions>
</Policy>`,
			wantNamed: "ObligationExpressions",
		},
		{
			name: "AdviceExpressions on a Policy",
			text: `<Policy PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Rule RuleId="r1" Effect="Permit"/>
  <AdviceExpressions></AdviceExpressions>
</Policy>`,
			wantNamed: "AdviceExpressions",
		},
		{
			name:      "PolicySet as the document root",
			text:      `<PolicySet PolicySetId="ps" PolicyCombiningAlgId="deny-overrides"></PolicySet>`,
			wantNamed: "PolicySet",
		},
		{
			name:      "PolicyIdReference as the document root",
			text:      `<PolicyIdReference>some-other-policy</PolicyIdReference>`,
			wantNamed: "PolicyIdReference",
		},
		{
			name:      "PolicySetIdReference as the document root",
			text:      `<PolicySetIdReference>some-other-policy-set</PolicySetIdReference>`,
			wantNamed: "PolicySetIdReference",
		},
		{
			name: "AttributeSelector in place of AttributeDesignator (XPath, not string-equal)",
			text: `<Policy PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Target>
    <AnyOf>
      <AllOf>
        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
          <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">x</AttributeValue>
          <AttributeSelector Path="//foo" DataType="http://www.w3.org/2001/XMLSchema#string"/>
        </Match>
      </AllOf>
    </AnyOf>
  </Target>
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`,
			wantNamed: "AttributeSelector",
		},
		{
			name: "VariableDefinition on a Policy",
			text: `<Policy PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <VariableDefinition VariableId="v1"></VariableDefinition>
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`,
			wantNamed: "VariableDefinition",
		},
		{
			name: "unsupported attribute on Policy (Version)",
			text: `<Policy PolicyId="p" Version="1.0" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`,
			wantNamed: "Version",
		},
		{
			name: "unsupported attribute on AttributeDesignator (MustBePresent)",
			text: `<Policy PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Target>
    <AnyOf>
      <AllOf>
        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
          <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">x</AttributeValue>
          <AttributeDesignator AttributeId="subject-id" DataType="http://www.w3.org/2001/XMLSchema#string" MustBePresent="true"/>
        </Match>
      </AllOf>
    </AnyOf>
  </Target>
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`,
			wantNamed: "MustBePresent",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := New().Validate(context.Background(), tc.text)
			if err == nil {
				t.Fatalf("Validate accepted a document containing %s, want an error (full XACML 3.0 is out of scope; this construct must be rejected, not silently ignored)", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantNamed) {
				t.Errorf("error does not name the unsupported construct %q: %v", tc.wantNamed, err)
			}
		})
	}
}

// TestValidate_TrailingContentIsRejected mirrors jsonpolicy's identical
// property for JSON: a StoredPolicy is one policy, and a document with two
// top-level elements has no single attributable meaning — accepting the
// first and silently ignoring the rest would be exactly the
// accept-and-ignore failure this package exists to prevent, just spelled
// as a second root element instead of an unsupported child.
func TestValidate_TrailingContentIsRejected(t *testing.T) {
	text := `<Policy PolicyId="p1" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>
<Policy PolicyId="p2" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Rule RuleId="r2" Effect="Deny"/>
</Policy>`
	if err := New().Validate(context.Background(), text); err == nil {
		t.Fatal("Validate accepted two <Policy> documents concatenated, want an error — a StoredPolicy is one policy")
	}
}

// TestValidate_EmptyDocumentIsRejected guards the walker's own "no root
// found" path — an empty or all-whitespace document has no Policy element
// to reject-by-name at all, and must still fail rather than vacuously
// validating.
func TestValidate_EmptyDocumentIsRejected(t *testing.T) {
	if err := New().Validate(context.Background(), ""); err == nil {
		t.Fatal("Validate accepted an empty document, want an error")
	}
}

// TestValidate_WrongRootElementNamesIt is the positive control isolating
// "wrong root name" from "any unsupported construct at all": the error
// must name the actual offending root element, not a generic parse
// failure indistinguishable from any other rejection.
func TestValidate_WrongRootElementNamesIt(t *testing.T) {
	err := New().Validate(context.Background(), `<NotAPolicy/>`)
	if err == nil {
		t.Fatal("Validate accepted a document whose root is not <Policy>, want an error")
	}
	if !strings.Contains(err.Error(), "NotAPolicy") {
		t.Errorf("error does not name the actual offending root element %q: %v", "NotAPolicy", err)
	}
}
