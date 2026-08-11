package xacml

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"stratium/internal/policy"
)

// TestValidate_NonDenyOverridesCombiningAlgIsRejected is the task brief's
// own required test and mutation target (c): permit-overrides inside a
// policy would let one rule's permit mask another's deny, contradicting
// this system's cross-policy fold and reopening exactly the local-combining
// hole this design removed everywhere else. Every case names an algorithm
// that is a real XACML 3.0 identifier, not a typo, so this test proves the
// engine rejects other *legitimate* algorithms deliberately, not merely
// unrecognized strings.
func TestValidate_NonDenyOverridesCombiningAlgIsRejected(t *testing.T) {
	cases := []string{
		"urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:permit-overrides",
		"urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable",
		"urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit",
		"urn:oasis:names:tc:xacml:1.1:rule-combining-algorithm:ordered-deny-overrides",
		"",
	}
	for _, alg := range cases {
		t.Run(alg, func(t *testing.T) {
			text := `<Policy PolicyId="p" RuleCombiningAlgId="` + alg + `">
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`
			err := New().Validate(context.Background(), text)
			if err == nil {
				t.Fatalf("Validate accepted RuleCombiningAlgId %q, want an error — only deny-overrides is supported", alg)
			}
		})
	}

	// Positive control: the exact deny-overrides URN must still validate,
	// so the checks above are rejecting other algorithms specifically, not
	// RuleCombiningAlgId in general.
	t.Run("deny-overrides itself is accepted", func(t *testing.T) {
		text := `<Policy PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`
		if err := New().Validate(context.Background(), text); err != nil {
			t.Fatalf("Validate rejected the exact deny-overrides URN: %v", err)
		}
	})
}

// TestValidate_MissingPolicyIDIsRejected checks PolicyId, required per the
// grammar in the package doc.
func TestValidate_MissingPolicyIDIsRejected(t *testing.T) {
	text := `<Policy PolicyId="" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`
	if err := New().Validate(context.Background(), text); err == nil {
		t.Fatal("Validate accepted an empty PolicyId, want an error")
	}
}

// TestValidate_ZeroRulesIsRejected guards a silently-dead-policy shape
// distinct from anything jsonpolicy or rego face: a <Policy> with a Target
// and no <Rule> children validates as syntactically complete XML and can
// never produce a verdict for any request, ever — the same "reads as a
// working policy, is actually permanently dead" defect class as a JSON
// policy missing its match block or an empty "in" list.
func TestValidate_ZeroRulesIsRejected(t *testing.T) {
	text := `<Policy PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Target/>
</Policy>`
	if err := New().Validate(context.Background(), text); err == nil {
		t.Fatal("Validate accepted a Policy with zero Rule elements, want an error — it could never produce a verdict for any request")
	}
}

// TestValidate_MissingRuleIDIsRejected and TestValidate_UnknownEffectIsRejected
// check Rule's own two required attributes.
func TestValidate_MissingRuleIDIsRejected(t *testing.T) {
	text := wrapPolicyNoBody(`<Rule RuleId="" Effect="Permit"/>`)
	if err := New().Validate(context.Background(), text); err == nil {
		t.Fatal("Validate accepted an empty RuleId, want an error")
	}
}

// TestValidate_UnknownEffectIsRejected checks the brief's grammar
// literally: Effect="Permit"|"Deny", exactly those two strings — XACML is
// normatively capitalized this way, so a lowercase or synonymous value is a
// realistic authoring mistake, not a contrived one.
func TestValidate_UnknownEffectIsRejected(t *testing.T) {
	cases := []string{"", "permit", "deny", "PERMIT", "Allow", "Deny "}
	for _, effect := range cases {
		t.Run(effect, func(t *testing.T) {
			text := wrapPolicyNoBody(`<Rule RuleId="r1" Effect="` + effect + `"/>`)
			if err := New().Validate(context.Background(), text); err == nil {
				t.Fatalf("Validate accepted Effect %q, want an error (only exactly \"Permit\" or \"Deny\" are legal)", effect)
			}
		})
	}
}

// wrapPolicyNoBody is wrapPolicy's counterpart for tests that replace the
// whole Rule element rather than inserting content inside one.
func wrapPolicyNoBody(rule string) string {
	return `<Policy PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  ` + rule + `
</Policy>`
}

// matchDoc builds a full, otherwise-valid Policy document around a single
// Match element — the shared shell for every MatchId/DataType/AttributeId/
// Category test below, so each test's fixture differs only in the one
// field it means to exercise. category is taken as an explicit parameter,
// not derived internally via categoryFor, specifically so
// TestValidate_WrongCategoryIsRejected (evaluate_test.go's sibling below)
// can pass a deliberately wrong one; every other caller passes
// categoryFor(attributeID) — the real value, reused rather than
// hand-copied, so those tests isolate the field they actually mean to
// exercise instead of incidentally also testing Category.
func matchDoc(matchID, valueDataType, designatorDataType, attributeID, category string) string {
	return `<Policy PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Target>
    <AnyOf>
      <AllOf>
        <Match MatchId="` + matchID + `">
          <AttributeValue DataType="` + valueDataType + `">x</AttributeValue>
          <AttributeDesignator AttributeId="` + attributeID + `" DataType="` + designatorDataType + `" Category="` + category + `"/>
        </Match>
      </AllOf>
    </AnyOf>
  </Target>
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`
}

const (
	wantMatchID  = "urn:oasis:names:tc:xacml:1.0:function:string-equal"
	wantDataType = "http://www.w3.org/2001/XMLSchema#string"
)

// TestValidate_NonStringEqualMatchIDIsRejected is the task brief's own
// required property, "string equality only": every function identifier
// other than string-equal is rejected, including ones that sound like
// harmless variants (ignore-case) and ones that are a different comparison
// entirely (integer-equal, regexp-match).
func TestValidate_NonStringEqualMatchIDIsRejected(t *testing.T) {
	cases := []string{
		"urn:oasis:names:tc:xacml:1.0:function:string-equal-ignore-case",
		"urn:oasis:names:tc:xacml:1.0:function:integer-equal",
		"urn:oasis:names:tc:xacml:1.0:function:string-regexp-match",
		"urn:oasis:names:tc:xacml:1.0:function:string-starts-with",
		"",
	}
	for _, matchID := range cases {
		t.Run(matchID, func(t *testing.T) {
			text := matchDoc(matchID, wantDataType, wantDataType, attrSubjectID, categorySubject)
			if err := New().Validate(context.Background(), text); err == nil {
				t.Fatalf("Validate accepted MatchId %q, want an error — string equality only", matchID)
			}
		})
	}
}

func TestValidate_NonStringDataTypeIsRejected(t *testing.T) {
	t.Run("AttributeValue", func(t *testing.T) {
		text := matchDoc(wantMatchID, "http://www.w3.org/2001/XMLSchema#integer", wantDataType, attrSubjectID, categorySubject)
		if err := New().Validate(context.Background(), text); err == nil {
			t.Fatal("Validate accepted a non-string AttributeValue DataType, want an error")
		}
	})
	t.Run("AttributeDesignator", func(t *testing.T) {
		text := matchDoc(wantMatchID, wantDataType, "http://www.w3.org/2001/XMLSchema#integer", attrSubjectID, categorySubject)
		if err := New().Validate(context.Background(), text); err == nil {
			t.Fatal("Validate accepted a non-string AttributeDesignator DataType, want an error")
		}
	})
}

// TestValidate_UnknownAttributeIDIsRejected guards the closed(-ish)
// AttributeId vocabulary the package doc documents as this engine's public
// surface: a name outside the fixed list and outside the subject:/resource:
// open prefixes can only be a typo, and accepting it would leave a rule
// that reads as constraining something but can never actually resolve —
// the same defect class jsonpolicy's agentAttrValue allow-list guards.
func TestValidate_UnknownAttributeIDIsRejected(t *testing.T) {
	cases := []string{
		"subject",          // missing the "-id" / ":" that would make it a real designator
		"agent-id",         // a real AgentInfo field, but not one this engine's vocabulary exposes
		"delegation-depth", // likewise: Delegation.Depth is real, not wired up
		"resource",         // missing "-id" / ":"
		"",
	}
	for _, attributeID := range cases {
		t.Run(attributeID, func(t *testing.T) {
			// categoryFor(attributeID) is used even for these unknown IDs:
			// attributeIDKnown rejects them before Category is ever
			// consulted (see (xmlMatch).validate's check order), so its
			// value here is irrelevant to what this subtest exercises —
			// but matchDoc always needs a syntactically real category URN
			// to isolate that this rejection is about AttributeId, not
			// Category.
			text := matchDoc(wantMatchID, wantDataType, wantDataType, attributeID, categoryFor(attributeID))
			if err := New().Validate(context.Background(), text); err == nil {
				t.Fatalf("Validate accepted AttributeId %q, want an error", attributeID)
			}
		})
	}

	// Positive control: every documented AttributeId, fixed and open-prefixed,
	// must still validate — the checks above reject unknown names
	// specifically, not AttributeId in general.
	known := []string{
		attrSubjectID, attrResourceID, attrActionID, attrAgentTrustTier,
		attrDelegationPurpose, attrDelegationMaxTier, attrDerivedTier,
		"subject:department", "resource:classification",
	}
	for _, attributeID := range known {
		t.Run("known: "+attributeID, func(t *testing.T) {
			// sampleValueFor: matchDoc's default AttributeValue text ("x")
			// is not a real enum spelling for the three tier-valued
			// designators, and would now fail the closed-vocabulary check
			// added alongside this one — substituting a real value here
			// keeps this subtest isolated to "is the AttributeId itself
			// accepted," not incidentally re-testing vocabulary too.
			text := matchDoc(wantMatchID, wantDataType, wantDataType, attributeID, categoryFor(attributeID))
			text = strings.Replace(text, ">x<", ">"+sampleValueFor(attributeID)+"<", 1)
			if err := New().Validate(context.Background(), text); err != nil {
				t.Fatalf("Validate rejected known AttributeId %q: %v", attributeID, err)
			}
		})
	}
}

// sampleValueFor returns an AttributeValue text that satisfies
// attributeID's own value constraints — "x" for every open-ended
// designator, and a real enum spelling for the three tier-valued ones
// (see (xmlMatch).validate's closed-vocabulary check). Shared by every
// test fixture below that only cares "this AttributeId validates," not
// what specific value it carries.
func sampleValueFor(attributeID string) string {
	switch attributeID {
	case attrAgentTrustTier:
		return agentTrustTierValues[0]
	case attrDerivedTier, attrDelegationMaxTier:
		return actionTierValues[0]
	default:
		return "x"
	}
}

// TestValidate_WrongCategoryIsRejected is Important 3's own required
// property: Category is real XACML schema machinery a general-purpose
// authoring tool emits unconditionally, and accepting it without checking
// it against the dimension its own AttributeId names would be exactly the
// "reads as configurable, isn't" trap this engine exists to close —
// silently indistinguishable from a designator whose Category the author
// mislabeled (a subject attribute tagged with the resource category, most
// plausibly from copy-pasting a Match and forgetting to update every
// field).
func TestValidate_WrongCategoryIsRejected(t *testing.T) {
	cases := []struct {
		name        string
		attributeID string
		wrongCat    string
	}{
		{"subject-id tagged resource", attrSubjectID, categoryResource},
		{"resource-id tagged subject", attrResourceID, categorySubject},
		{"action-id tagged environment", attrActionID, categoryEnvironment},
		{"agent-trust-tier (environment) tagged subject", attrAgentTrustTier, categorySubject},
		{"empty Category", attrSubjectID, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// sampleValueFor: a real enum spelling for agent-trust-tier, so
			// only Category is under test here, not incidentally the
			// vocabulary check too.
			text := matchDoc(wantMatchID, wantDataType, wantDataType, tc.attributeID, tc.wrongCat)
			text = strings.Replace(text, ">x<", ">"+sampleValueFor(tc.attributeID)+"<", 1)
			if err := New().Validate(context.Background(), text); err == nil {
				t.Fatalf("Validate accepted AttributeId %q with Category %q, want an error", tc.attributeID, tc.wrongCat)
			}
		})
	}

	// Positive control: every documented AttributeId with its OWN correct
	// Category must still validate — proving the checks above reject a
	// mismatch specifically, not Category (or these particular
	// AttributeIds) in general. TestValidate_UnknownAttributeIDIsRejected's
	// own "known" subtests already cover this for every designator using
	// categoryFor uniformly; this positive control is deliberately
	// duplicated here, once, so this test file is self-contained proof
	// that a *correct* Category is never the thing being rejected.
	t.Run("correct category is accepted", func(t *testing.T) {
		text := matchDoc(wantMatchID, wantDataType, wantDataType, attrSubjectID, categorySubject)
		if err := New().Validate(context.Background(), text); err != nil {
			t.Fatalf("Validate rejected a correct Category: %v", err)
		}
	})
}

// TestValidate_TierValueVocabularyIsRejected is Important 2's own required
// property: agent-trust-tier, derived-tier, and delegation-max-tier each
// read a closed Go enum (see resolveAttr), and an AttributeValue outside
// that enum's real String() spellings validates cleanly today and can
// never match anything the engine actually produces — the same defect
// class BASE commit 6abf998 fixed for jsonpolicy's own "in": [] one commit
// before this engine existed.
func TestValidate_TierValueVocabularyIsRejected(t *testing.T) {
	cases := []struct {
		name        string
		attributeID string
		value       string
	}{
		{"agent-trust-tier wrong case", attrAgentTrustTier, "Certified"},
		{"agent-trust-tier made up", attrAgentTrustTier, "SUPER_TRUSTED"},
		{"derived-tier as an ordinal digit", attrDerivedTier, "3"},
		{"derived-tier hyphen instead of underscore", attrDerivedTier, "EXTERNAL-COMMS"},
		{"delegation-max-tier made up", attrDelegationMaxTier, "READONLY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := matchDoc(wantMatchID, wantDataType, wantDataType, tc.attributeID, categoryFor(tc.attributeID))
			text = strings.Replace(text, ">x<", ">"+tc.value+"<", 1)
			if err := New().Validate(context.Background(), text); err == nil {
				t.Fatalf("Validate accepted %s = %q, want an error (not a real enum value)", tc.attributeID, tc.value)
			}
		})
	}

	// Positive control: a real spelling for each of the three tier-valued
	// designators must still validate.
	positive := []struct {
		attributeID, value string
	}{
		{attrAgentTrustTier, "CERTIFIED"},
		{attrDerivedTier, "DESTRUCTIVE"},
		{attrDelegationMaxTier, "EXTERNAL_COMMS"},
	}
	for _, tc := range positive {
		t.Run("real value: "+tc.attributeID+"="+tc.value, func(t *testing.T) {
			text := matchDoc(wantMatchID, wantDataType, wantDataType, tc.attributeID, categoryFor(tc.attributeID))
			text = strings.Replace(text, ">x<", ">"+tc.value+"<", 1)
			if err := New().Validate(context.Background(), text); err != nil {
				t.Fatalf("Validate rejected a real enum value %s = %q: %v", tc.attributeID, tc.value, err)
			}
		})
	}
}

// TestValidate_PaddedAttributeValueIsRejected is Important 4's own
// required property: xs:string preserves surrounding whitespace verbatim,
// so a value written across lines — ordinary XML formatting, and the one
// style every fixture in this package wrote inline specifically to avoid
// hitting this — compares against the padded string and can never match.
func TestValidate_PaddedAttributeValueIsRejected(t *testing.T) {
	cases := []string{
		"\n  alice\n",
		" alice",
		"alice ",
		"\talice",
	}
	for _, value := range cases {
		t.Run(fmt.Sprintf("%q", value), func(t *testing.T) {
			text := matchDoc(wantMatchID, wantDataType, wantDataType, attrSubjectID, categorySubject)
			text = strings.Replace(text, ">x<", ">"+value+"<", 1)
			if err := New().Validate(context.Background(), text); err == nil {
				t.Fatalf("Validate accepted AttributeValue %q with surrounding whitespace, want an error", value)
			}
		})
	}

	// Positive control: the trimmed form must still validate — proving the
	// checks above reject the whitespace specifically, not the value "alice"
	// or AttributeValue in general.
	t.Run("inline value with no surrounding whitespace is accepted", func(t *testing.T) {
		text := matchDoc(wantMatchID, wantDataType, wantDataType, attrSubjectID, categorySubject)
		text = strings.Replace(text, ">x<", ">alice<", 1)
		if err := New().Validate(context.Background(), text); err != nil {
			t.Fatalf("Validate rejected an inline value with no surrounding whitespace: %v", err)
		}
	})
}

// TestValidate_EmptyOpenAttributeKeyIsRejected is the Minor finding: a bare
// "subject:" or "resource:" (the right shape, no key after the colon) has
// the right shape to look like a real open designator but can never
// resolve to anything — Principal.Attributes[""] and Resource[""] are not
// what any author means to write — the same permanently-dead-by-
// construction shape as an empty "in" list, distinct from a typo'd real
// key (which merely never matches, the safe direction).
func TestValidate_EmptyOpenAttributeKeyIsRejected(t *testing.T) {
	cases := []string{"subject:", "resource:"}
	for _, attributeID := range cases {
		t.Run(attributeID, func(t *testing.T) {
			text := matchDoc(wantMatchID, wantDataType, wantDataType, attributeID, categoryFor(attributeID))
			if err := New().Validate(context.Background(), text); err == nil {
				t.Fatalf("Validate accepted AttributeId %q (empty key after the prefix), want an error", attributeID)
			}
		})
	}

	// Positive control: a real key after the same prefixes must still
	// validate — proving the checks above reject emptiness specifically,
	// not the subject:/resource: prefixes in general.
	t.Run("a real key is still accepted", func(t *testing.T) {
		text := matchDoc(wantMatchID, wantDataType, wantDataType, "subject:department", categorySubject)
		if err := New().Validate(context.Background(), text); err != nil {
			t.Fatalf("Validate rejected subject:department: %v", err)
		}
	})
}

// TestValidate_EmptyAnyOfAndAllOfAreRejected pins the asymmetry the package
// doc calls out explicitly: an empty Target means "matches everything" (a
// real, useful, spec-defined meaning), but an empty AnyOf or AllOf has no
// such defined meaning and is rejected instead of silently guessing one.
func TestValidate_EmptyAnyOfAndAllOfAreRejected(t *testing.T) {
	t.Run("AnyOf with zero AllOf", func(t *testing.T) {
		text := `<Policy PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Target>
    <AnyOf/>
  </Target>
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`
		if err := New().Validate(context.Background(), text); err == nil {
			t.Fatal("Validate accepted an AnyOf with zero AllOf children, want an error")
		}
	})
	t.Run("AllOf with zero Match", func(t *testing.T) {
		text := `<Policy PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Target>
    <AnyOf>
      <AllOf/>
    </AnyOf>
  </Target>
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`
		if err := New().Validate(context.Background(), text); err == nil {
			t.Fatal("Validate accepted an AllOf with zero Match children, want an error")
		}
	})

	// Positive control: an empty Target itself (the one meaningful empty
	// case) must still validate — see TestEvaluate_EmptyTargetMatchesEverything
	// for the behavioural half of this property.
	t.Run("empty Target itself is accepted", func(t *testing.T) {
		text := `<Policy PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Target/>
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`
		if err := New().Validate(context.Background(), text); err != nil {
			t.Fatalf("Validate rejected an empty <Target/>, want success: %v", err)
		}
	})
}

// TestPrepare_NamesMalformedPolicy pins the same property
// policytest.EngineContract already checks (testPrepareNamesMalformedPolicy)
// against a schema-specific malformed shape: syntactically well-formed XML
// that fails this schema's own semantic validation (zero Rules), rather
// than the shared contract's plain XML syntax error. A Prepare that checked
// only the XML parse error and skipped xmlPolicy-level validation would
// still be caught here, even though it would pass the contract's own
// Fixtures.Malformed (a real syntax error) undetected.
func TestPrepare_NamesMalformedPolicy(t *testing.T) {
	const (
		malformedID = "malformed-under-test"
		neighborID  = "well-formed-neighbor"
	)
	neighborText := `<Policy PolicyId="np" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`
	malformedText := `<Policy PolicyId="mp" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
</Policy>`

	policies := []policy.StoredPolicy{
		{ID: neighborID, Name: "neighbor", Language: language, Text: neighborText, Priority: 1, Version: 1},
		{ID: malformedID, Name: "quarantine-me", Language: language, Text: malformedText, Priority: 1, Version: 1},
	}
	_, err := New().Prepare(context.Background(), policies)
	if err == nil {
		t.Fatal("Prepare accepted a policy set containing a Policy with zero Rule elements, want an error")
	}
	if !strings.Contains(err.Error(), malformedID) {
		t.Errorf("Prepare error does not name the offending policy's ID %q: %v", malformedID, err)
	}
	if strings.Contains(err.Error(), neighborID) {
		t.Errorf("Prepare error blames the well-formed neighbor %q instead of (or as well as) the offender: %v", neighborID, err)
	}
}
