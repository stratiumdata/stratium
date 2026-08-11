package xacml

import (
	"context"
	"strings"
	"testing"

	"stratium/internal/authz"
	"stratium/internal/policy"
	"stratium/pkg/models"
)

// prepareOne is the shared setup every test below needs: one StoredPolicy,
// prepared, ready to Evaluate.
func prepareOne(t *testing.T, text string) policy.CompiledPolicySet {
	t.Helper()
	set, err := New().Prepare(context.Background(), []policy.StoredPolicy{
		{ID: "p1", Name: "under-test", Language: language, Text: text, Effect: "allow", Priority: 7, Version: 1},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return set
}

func evaluate(t *testing.T, set policy.CompiledPolicySet, in policy.EvaluationInput) []authz.PolicyVerdict {
	t.Helper()
	verdicts, err := set.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return verdicts
}

// subjectMatchPolicy builds a Policy whose sole Rule fires with effect when
// its Target's one Match (subject-id equals wantSubject) is satisfied — the
// shared shell for the permit/deny/non-match trio below.
func subjectMatchPolicy(effect, wantSubject string) string {
	return `<Policy PolicyId="p1" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Target>
    <AnyOf>
      <AllOf>
        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
          <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">` + wantSubject + `</AttributeValue>
          <AttributeDesignator AttributeId="subject-id" DataType="http://www.w3.org/2001/XMLSchema#string"/>
        </Match>
      </AllOf>
    </AnyOf>
  </Target>
  <Rule RuleId="r1" Effect="` + effect + `"/>
</Policy>`
}

// TestEvaluate_PermitRuleMatching is the task brief's own required test: a
// permit rule matching produces exactly one EffectAllow verdict.
func TestEvaluate_PermitRuleMatching(t *testing.T) {
	set := prepareOne(t, subjectMatchPolicy(effectPermit, "alice"))
	verdicts := evaluate(t, set, policy.EvaluationInput{Principal: authz.Principal{Subject: "alice"}})

	if len(verdicts) != 1 {
		t.Fatalf("got %d verdicts, want 1: %+v", len(verdicts), verdicts)
	}
	if verdicts[0].Effect != authz.EffectAllow {
		t.Errorf("Effect = %v, want EffectAllow", verdicts[0].Effect)
	}
	if verdicts[0].PolicyID != "p1" {
		t.Errorf("PolicyID = %q, want %q", verdicts[0].PolicyID, "p1")
	}
}

// TestEvaluate_DenyRuleMatching is the task brief's own required test: a
// deny rule matching produces exactly one EffectDeny verdict.
func TestEvaluate_DenyRuleMatching(t *testing.T) {
	set := prepareOne(t, subjectMatchPolicy(effectDeny, "mallory"))
	verdicts := evaluate(t, set, policy.EvaluationInput{Principal: authz.Principal{Subject: "mallory"}})

	if len(verdicts) != 1 {
		t.Fatalf("got %d verdicts, want 1: %+v", len(verdicts), verdicts)
	}
	if verdicts[0].Effect != authz.EffectDeny {
		t.Errorf("Effect = %v, want EffectDeny", verdicts[0].Effect)
	}
}

// TestEvaluate_NonMatchingTargetYieldsNoVerdict is the task brief's own
// required test: a Policy whose Target excludes the request contributes
// nothing at all — not a deny, not an allow, and not the manufactured
// "default deny" verdict some other layer (authz.FoldVerdicts) is
// responsible for. Distinguishing "no verdict" from "a deny verdict" is
// exactly what tells apart this case from the Indeterminate case below,
// which must NOT collapse into it.
func TestEvaluate_NonMatchingTargetYieldsNoVerdict(t *testing.T) {
	set := prepareOne(t, subjectMatchPolicy(effectPermit, "alice"))
	verdicts := evaluate(t, set, policy.EvaluationInput{Principal: authz.Principal{Subject: "bob"}})

	if len(verdicts) != 0 {
		t.Fatalf("got %d verdicts for a non-matching target, want 0: %+v", len(verdicts), verdicts)
	}
}

// TestEvaluate_IndeterminateDesignatorDenies is the task brief's central
// semantic requirement, stated as a mandatory, deliberate branch rather
// than a default: an unresolvable attribute designator is Indeterminate,
// and Indeterminate is a deny — never a skip (which would read
// indistinguishably from "the target legitimately did not match," the
// previous test) and never silently folded away. subject:department reads
// Principal.Attributes["department"], which the zero-valued Principal
// below does not carry — a genuine "cannot resolve," not "resolved to
// empty string."
func TestEvaluate_IndeterminateDesignatorDenies(t *testing.T) {
	text := `<Policy PolicyId="p1" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Target>
    <AnyOf>
      <AllOf>
        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
          <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">finance</AttributeValue>
          <AttributeDesignator AttributeId="subject:department" DataType="http://www.w3.org/2001/XMLSchema#string"/>
        </Match>
      </AllOf>
    </AnyOf>
  </Target>
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`
	set := prepareOne(t, text)

	// Principal.Attributes is nil: "department" cannot resolve.
	verdicts := evaluate(t, set, policy.EvaluationInput{Principal: authz.Principal{Subject: "alice"}})

	if len(verdicts) != 1 {
		t.Fatalf("got %d verdicts for an unresolvable designator, want exactly 1 (a deny): %+v", len(verdicts), verdicts)
	}
	if verdicts[0].Effect != authz.EffectDeny {
		t.Errorf("Effect = %v, want EffectDeny — Indeterminate must deny, not skip", verdicts[0].Effect)
	}
	if !strings.Contains(verdicts[0].Reason, "subject:department") {
		t.Errorf("Reason does not name the unresolvable designator: %q", verdicts[0].Reason)
	}
	if !strings.Contains(verdicts[0].Reason, "Indeterminate") {
		t.Errorf("Reason does not say Indeterminate: %q", verdicts[0].Reason)
	}

	// Positive control: the same policy, given a Principal that DOES carry
	// the department attribute, resolves normally rather than being
	// permanently broken — Indeterminate is a property of the request, not
	// of the policy.
	t.Run("resolves normally once the attribute is present", func(t *testing.T) {
		in := policy.EvaluationInput{Principal: authz.Principal{Subject: "alice", Attributes: map[string]string{"department": "finance"}}}
		verdicts := evaluate(t, set, in)
		if len(verdicts) != 1 || verdicts[0].Effect != authz.EffectAllow {
			t.Fatalf("got %+v, want exactly one EffectAllow verdict", verdicts)
		}
	})
}

// TestEvaluate_IndeterminateAtRuleTargetDenies is
// TestEvaluate_IndeterminateDesignatorDenies's counterpart for a Rule-level
// Target rather than the Policy's own: a different code path
// (compiledPolicy.evaluate's rule loop, not its own target check) that
// must reach the identical fail-closed outcome.
func TestEvaluate_IndeterminateAtRuleTargetDenies(t *testing.T) {
	text := `<Policy PolicyId="p1" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Rule RuleId="r1" Effect="Permit">
    <Target>
      <AnyOf>
        <AllOf>
          <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
            <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">restricted</AttributeValue>
            <AttributeDesignator AttributeId="resource:classification" DataType="http://www.w3.org/2001/XMLSchema#string"/>
          </Match>
        </AllOf>
      </AnyOf>
    </Target>
  </Rule>
</Policy>`
	set := prepareOne(t, text)

	// Resource is nil: "classification" cannot resolve. The Policy's own
	// (absent) Target matches everything, so evaluation reaches the Rule.
	verdicts := evaluate(t, set, policy.EvaluationInput{Principal: authz.Principal{Subject: "alice"}})

	if len(verdicts) != 1 {
		t.Fatalf("got %d verdicts, want exactly 1 (a deny): %+v", len(verdicts), verdicts)
	}
	if verdicts[0].Effect != authz.EffectDeny {
		t.Errorf("Effect = %v, want EffectDeny", verdicts[0].Effect)
	}
	if !strings.Contains(verdicts[0].Reason, "resource:classification") {
		t.Errorf("Reason does not name the unresolvable designator: %q", verdicts[0].Reason)
	}
}

// TestEvaluate_DenyOverridesWithinPolicy checks the one combining decision
// this package implements: within a single Policy, a matched Deny rule
// wins over a matched Permit rule, regardless of which is declared first —
// proving this is genuine deny-overrides, not "first rule wins" or "last
// rule wins" by accident.
func TestEvaluate_DenyOverridesWithinPolicy(t *testing.T) {
	build := func(rules string) string {
		return `<Policy PolicyId="p1" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">` + rules + `</Policy>`
	}
	permitRule := `<Rule RuleId="permit-rule" Effect="Permit"/>`
	denyRule := `<Rule RuleId="deny-rule" Effect="Deny"/>`

	t.Run("deny declared after permit still wins", func(t *testing.T) {
		set := prepareOne(t, build(permitRule+denyRule))
		verdicts := evaluate(t, set, policy.EvaluationInput{})
		if len(verdicts) != 1 || verdicts[0].Effect != authz.EffectDeny {
			t.Fatalf("got %+v, want exactly one EffectDeny verdict", verdicts)
		}
	})

	t.Run("deny declared before permit still wins", func(t *testing.T) {
		set := prepareOne(t, build(denyRule+permitRule))
		verdicts := evaluate(t, set, policy.EvaluationInput{})
		if len(verdicts) != 1 || verdicts[0].Effect != authz.EffectDeny {
			t.Fatalf("got %+v, want exactly one EffectDeny verdict", verdicts)
		}
	})
}

// TestEvaluate_EmptyTargetMatchesEverything pins the one deliberately
// meaningful empty case in this grammar (see the package doc and
// (*xmlTarget).evaluate's own comment): a Target present with zero AnyOf,
// and a Target entirely absent, both mean "applies unconditionally" — a
// spec-defined special case, not the "OR of nothing is false" a naive
// empty-slice loop would fall through to.
func TestEvaluate_EmptyTargetMatchesEverything(t *testing.T) {
	t.Run("Target present but empty", func(t *testing.T) {
		text := `<Policy PolicyId="p1" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Target/>
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`
		set := prepareOne(t, text)
		verdicts := evaluate(t, set, policy.EvaluationInput{})
		if len(verdicts) != 1 || verdicts[0].Effect != authz.EffectAllow {
			t.Fatalf("got %+v, want exactly one EffectAllow verdict", verdicts)
		}
	})

	t.Run("Target entirely absent", func(t *testing.T) {
		text := `<Policy PolicyId="p1" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`
		set := prepareOne(t, text)
		verdicts := evaluate(t, set, policy.EvaluationInput{})
		if len(verdicts) != 1 || verdicts[0].Effect != authz.EffectAllow {
			t.Fatalf("got %+v, want exactly one EffectAllow verdict", verdicts)
		}
	})
}

// TestEvaluate_AnyOfIsDisjunctionOfAllOfConjunctions pins the DNF structure
// the package doc promises: Target = OR of AnyOf's AllOf branches, each
// AllOf = AND of its Matches. A single branch or a single Match failing
// must not sink the whole Target if another AnyOf branch is fully
// satisfied; a single Match failing WITHIN the satisfied branch must sink
// that branch.
func TestEvaluate_AnyOfIsDisjunctionOfAllOfConjunctions(t *testing.T) {
	// Two AnyOf branches: the first requires (subject-id=alice AND
	// action-id=Bash) — a conjunction this input only half-satisfies — the
	// second requires only subject-id=alice. A correct OR-of-AND
	// evaluation matches via the second branch; a buggy implementation that
	// flattened everything into one AND would not.
	text := `<Policy PolicyId="p1" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Target>
    <AnyOf>
      <AllOf>
        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
          <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">alice</AttributeValue>
          <AttributeDesignator AttributeId="subject-id" DataType="http://www.w3.org/2001/XMLSchema#string"/>
        </Match>
        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
          <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">Bash</AttributeValue>
          <AttributeDesignator AttributeId="action-id" DataType="http://www.w3.org/2001/XMLSchema#string"/>
        </Match>
      </AllOf>
    </AnyOf>
    <AnyOf>
      <AllOf>
        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
          <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">alice</AttributeValue>
          <AttributeDesignator AttributeId="subject-id" DataType="http://www.w3.org/2001/XMLSchema#string"/>
        </Match>
      </AllOf>
    </AnyOf>
  </Target>
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`
	set := prepareOne(t, text)

	in := policy.EvaluationInput{Principal: authz.Principal{Subject: "alice"}, Action: authz.Action{Tool: "Read"}}
	verdicts := evaluate(t, set, in)
	if len(verdicts) != 1 || verdicts[0].Effect != authz.EffectAllow {
		t.Fatalf("got %+v, want exactly one EffectAllow verdict via the second AnyOf branch", verdicts)
	}

	// Positive control: a subject satisfying NEITHER branch's AllOf must
	// not match — proves the second AnyOf branch actually constrains
	// something rather than the Target degrading to always-true.
	t.Run("subject satisfying neither branch does not match", func(t *testing.T) {
		in := policy.EvaluationInput{Principal: authz.Principal{Subject: "bob"}, Action: authz.Action{Tool: "Read"}}
		verdicts := evaluate(t, set, in)
		if len(verdicts) != 0 {
			t.Fatalf("got %+v, want zero verdicts", verdicts)
		}
	})
}

// TestEvaluate_AttributeDesignators exercises every entry in the package
// doc's designator table end to end — Match against a real
// EvaluationInput, not just Validate accepting the name — so a mapping
// bug (reading the wrong field, a typo'd map key) fails here even if the
// name itself is spelled correctly in schema.go's vocabulary.
func TestEvaluate_AttributeDesignators(t *testing.T) {
	cases := []struct {
		name        string
		attributeID string
		value       string
		in          policy.EvaluationInput
	}{
		{"subject-id", attrSubjectID, "alice", policy.EvaluationInput{Principal: authz.Principal{Subject: "alice"}}},
		{"subject:<key>", "subject:team", "payments", policy.EvaluationInput{Principal: authz.Principal{Attributes: map[string]string{"team": "payments"}}}},
		{"resource-id", attrResourceID, "doc-42", policy.EvaluationInput{Resource: map[string]string{"id": "doc-42"}}},
		{"resource:<key>", "resource:classification", "restricted", policy.EvaluationInput{Resource: map[string]string{"classification": "restricted"}}},
		{"action-id", attrActionID, "Bash", policy.EvaluationInput{Action: authz.Action{Tool: "Bash"}}},
		{"agent-trust-tier", attrAgentTrustTier, "CERTIFIED", policy.EvaluationInput{Agent: authz.AgentInfo{TrustTier: models.TrustTierCertified}}},
		{"delegation-purpose", attrDelegationPurpose, "quarterly-close", policy.EvaluationInput{Delegation: policy.DelegationContext{Purpose: "quarterly-close"}}},
		{"delegation-max-tier", attrDelegationMaxTier, "EXTERNAL_COMMS", policy.EvaluationInput{Delegation: policy.DelegationContext{MaxActionTier: models.ActionTierExternalComms}}},
		{"derived-tier", attrDerivedTier, "DESTRUCTIVE", policy.EvaluationInput{DerivedTier: models.ActionTierDestructive}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := matchDoc(wantMatchID, wantDataType, wantDataType, tc.attributeID)
			// matchDoc's AttributeValue text is fixed to "x"; swap it for
			// this case's expected value so the comparison is meaningful.
			text = strings.Replace(text, ">x<", ">"+tc.value+"<", 1)
			set := prepareOne(t, text)

			verdicts := evaluate(t, set, tc.in)
			if len(verdicts) != 1 || verdicts[0].Effect != authz.EffectAllow {
				t.Fatalf("%s: got %+v, want exactly one EffectAllow verdict (designator resolved to %q)", tc.attributeID, verdicts, tc.value)
			}
		})
	}
}
