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

// TestValidate_RepeatedBoundedElementIsRejected is the review's Critical
// finding: grammar's children map says which names may appear, never how
// many times, and xml.Unmarshal binds Policy's Target, Rule's Target, and
// Match's AttributeValue/AttributeDesignator to non-slice Go fields — a
// second occurrence of any of these used to be silently accepted by
// Validate and then silently mis-evaluated (the first AttributeValue or
// AttributeDesignator discarded in favor of the second; two Targets OR-ed
// together, which can only widen — never narrow — what a Policy or Rule
// applies to). Each case below is verified to have actually reproduced
// that pre-fix behavior before this test was written to guard it — see the
// report's mutation-testing section.
func TestValidate_RepeatedBoundedElementIsRejected(t *testing.T) {
	target := `<Target><AnyOf><AllOf><Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">x</AttributeValue><AttributeDesignator AttributeId="subject-id" DataType="http://www.w3.org/2001/XMLSchema#string" Category="` + categorySubject + `"/></Match></AllOf></AnyOf></Target>`

	cases := []struct {
		name string
		text string
	}{
		{
			name: "duplicate Target on Policy",
			text: `<Policy PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">` + target + target + `<Rule RuleId="r1" Effect="Permit"/></Policy>`,
		},
		{
			name: "duplicate Target on Rule",
			text: `<Policy PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides"><Rule RuleId="r1" Effect="Permit">` + target + target + `</Rule></Policy>`,
		},
		{
			name: "duplicate AttributeValue in Match",
			text: wrapPolicy(`<Target><AnyOf><AllOf><Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">alice</AttributeValue><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">bob</AttributeValue><AttributeDesignator AttributeId="subject-id" DataType="http://www.w3.org/2001/XMLSchema#string" Category="` + categorySubject + `"/></Match></AllOf></AnyOf></Target>`),
		},
		{
			name: "duplicate AttributeDesignator in Match",
			text: wrapPolicy(`<Target><AnyOf><AllOf><Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">Bash</AttributeValue><AttributeDesignator AttributeId="subject-id" DataType="http://www.w3.org/2001/XMLSchema#string" Category="` + categorySubject + `"/><AttributeDesignator AttributeId="action-id" DataType="http://www.w3.org/2001/XMLSchema#string" Category="` + categoryAction + `"/></Match></AllOf></AnyOf></Target>`),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := New().Validate(context.Background(), tc.text)
			if err == nil {
				t.Fatalf("Validate accepted %s, want an error — a duplicate here silently changes meaning instead of failing to compile", tc.name)
			}
		})
	}

	// Positive control: a single Target / AttributeValue / AttributeDesignator
	// must still validate — the checks above reject a *second* occurrence
	// specifically, not the element at all.
	t.Run("a single Target, AttributeValue, and AttributeDesignator are still accepted", func(t *testing.T) {
		text := `<Policy PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">` + target + `<Rule RuleId="r1" Effect="Permit">` + target + `</Rule></Policy>`
		if err := New().Validate(context.Background(), text); err != nil {
			t.Fatalf("Validate rejected a document with exactly one Target at each level: %v", err)
		}
	})
}

// TestValidate_NamespaceDeclarationIsAccepted is Important 3's own required
// property: a real, schema-valid XACML 3.0 document declares a namespace
// (typically the default xmlns, sometimes a prefix), and this engine used
// to reject exactly that — the more spec-conformant document was the one
// that failed, while the same document with its prefix left undeclared
// (not well-formed XML by a validating processor's standard, but silently
// accepted here on account of matching local names only) passed. Both
// forms below must now behave identically.
func TestValidate_NamespaceDeclarationIsAccepted(t *testing.T) {
	base := `<Rule RuleId="r1" Effect="Permit"/>`

	t.Run("default xmlns on the root", func(t *testing.T) {
		text := `<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">` + base + `</Policy>`
		if err := New().Validate(context.Background(), text); err != nil {
			t.Fatalf("Validate rejected a document declaring the standard default xmlns: %v", err)
		}
	})

	t.Run("prefixed namespace, properly declared", func(t *testing.T) {
		text := `<x:Policy xmlns:x="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">` + base + `</x:Policy>`
		if err := New().Validate(context.Background(), text); err != nil {
			t.Fatalf("Validate rejected a document with a properly declared namespace prefix: %v", err)
		}
	})

	// Symmetry check: the same prefixed document with its prefix left
	// UNdeclared must behave identically to the properly declared form
	// above — both accepted, matching on local name only either way. This
	// is the other half of the asymmetry review found: before the fix,
	// this (less correct) form was the one that passed, and the properly
	// declared form above was the one that failed.
	t.Run("prefixed namespace, undeclared prefix, behaves the same", func(t *testing.T) {
		text := `<x:Policy PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">` + base + `</x:Policy>`
		if err := New().Validate(context.Background(), text); err != nil {
			t.Fatalf("Validate rejected a document with an undeclared namespace prefix: %v", err)
		}
	})
}

// TestValidate_StrayTextContentIsRejected is the review's Minor finding:
// chardata was never inspected, so text sitting where only child elements
// or nothing at all belongs — inside <Policy>, <Rule>, or
// <AttributeDesignator> (always a leaf) — was silently dropped by
// xml.Unmarshal, the same silent-discard mechanism as an unsupported
// element, just carrying no structural name to report.
func TestValidate_StrayTextContentIsRejected(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{
			name: "text inside AttributeDesignator",
			text: wrapPolicy(`<Target><AnyOf><AllOf><Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">x</AttributeValue><AttributeDesignator AttributeId="subject-id" DataType="http://www.w3.org/2001/XMLSchema#string" Category="` + categorySubject + `">SURPRISE</AttributeDesignator></Match></AllOf></AnyOf></Target>`),
		},
		{
			name: "text directly inside Policy",
			text: `<Policy PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">SURPRISE<Rule RuleId="r1" Effect="Permit"/></Policy>`,
		},
		{
			name: "text directly inside Rule",
			text: wrapPolicy(`SURPRISE`),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := New().Validate(context.Background(), tc.text); err == nil {
				t.Fatalf("Validate accepted stray text content (%s), want an error", tc.name)
			}
		})
	}

	// Positive control: ordinary whitespace-only formatting (the
	// indentation and newlines every fixture in this package uses between
	// elements) must not be rejected — only non-whitespace text is a
	// problem.
	t.Run("whitespace-only formatting between elements is accepted", func(t *testing.T) {
		text := "<Policy PolicyId=\"p\" RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides\">\n  \n\t<Rule RuleId=\"r1\" Effect=\"Permit\"/>\n</Policy>"
		if err := New().Validate(context.Background(), text); err != nil {
			t.Fatalf("Validate rejected whitespace-only formatting between elements: %v", err)
		}
	})
}
