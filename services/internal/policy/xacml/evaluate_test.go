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
          <AttributeDesignator AttributeId="subject-id" DataType="http://www.w3.org/2001/XMLSchema#string" Category="` + categorySubject + `"/>
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
          <AttributeDesignator AttributeId="subject:department" DataType="http://www.w3.org/2001/XMLSchema#string" Category="` + categorySubject + `"/>
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
            <AttributeDesignator AttributeId="resource:classification" DataType="http://www.w3.org/2001/XMLSchema#string" Category="` + categoryResource + `"/>
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

// TestEvaluate_RuleLevelDefiniteNonMatchIsSkipped pins evaluate.go's rule
// loop `if !rMatched { continue }` branch directly. Review found this
// branch had no behavioural test of its own: every existing Rule-level
// Target fixture in this package either matched or was Indeterminate — a
// resolvable designator whose value simply differs (a genuine, definite
// non-match) was never exercised. Rule 1's Deny only fires if a
// non-matching Target is wrongly treated as a match; Rule 2's
// unconditional Permit only wins if Rule 1 is correctly skipped rather
// than, say, denying by default or short-circuiting the rest of the loop.
func TestEvaluate_RuleLevelDefiniteNonMatchIsSkipped(t *testing.T) {
	text := `<Policy PolicyId="p1" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Rule RuleId="deny-if-bash" Effect="Deny">
    <Target>
      <AnyOf>
        <AllOf>
          <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
            <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">Bash</AttributeValue>
            <AttributeDesignator AttributeId="action-id" DataType="http://www.w3.org/2001/XMLSchema#string" Category="` + categoryAction + `"/>
          </Match>
        </AllOf>
      </AnyOf>
    </Target>
  </Rule>
  <Rule RuleId="permit-all" Effect="Permit"/>
</Policy>`
	set := prepareOne(t, text)

	verdicts := evaluate(t, set, policy.EvaluationInput{Action: authz.Action{Tool: "Read"}})
	if len(verdicts) != 1 || verdicts[0].Effect != authz.EffectAllow {
		t.Fatalf(`got %+v, want exactly one EffectAllow verdict — the Deny rule's Target definitely does not match (action-id is "Read", not "Bash") and must be skipped, not fire`, verdicts)
	}

	// Positive control: the same policy, given an action that DOES match
	// the first rule's Target, denies — proving the skip above is real
	// (Target-conditioned), not the Deny rule being unreachable for some
	// unrelated reason (e.g. a typo in the fixture).
	t.Run("the same Target does fire on a genuinely matching action", func(t *testing.T) {
		verdicts := evaluate(t, set, policy.EvaluationInput{Action: authz.Action{Tool: "Bash"}})
		if len(verdicts) != 1 || verdicts[0].Effect != authz.EffectDeny {
			t.Fatalf("got %+v, want exactly one EffectDeny verdict", verdicts)
		}
	})
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

// TestEvaluate_TargetIsConjunctionOfAnyOfDisjunctions pins the actual XACML
// 3.0 structure the package doc now describes: Target = AND across every
// AnyOf (§5.5: "The <Target> element SHALL contain a conjunctive sequence
// of <AnyOf> elements"; §7.7 Table 4: a Target is "No Match" if at least
// one <AnyOf> is "No Match"), each AnyOf itself = OR across its AllOf
// branches, each AllOf = AND across its Matches. This test used to assert
// the Target level was ALSO a disjunction — the bug (*xmlTarget).evaluate
// has since been fixed to no longer have. A single AnyOf branch failing
// must now sink the whole Target even if another AnyOf branch is fully
// satisfied; a single Match failing WITHIN one AnyOf's AllOf must still
// sink that branch (still exercised below, via the first AnyOf's two-Match
// conjunction).
func TestEvaluate_TargetIsConjunctionOfAnyOfDisjunctions(t *testing.T) {
	// Two AnyOf branches: the first requires (subject-id=alice AND
	// action-id=Bash) — a conjunction — the second requires only
	// subject-id=alice. Per §5.5 the Target as a whole matches only when
	// BOTH AnyOf branches match, not either alone.
	text := `<Policy PolicyId="p1" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Target>
    <AnyOf>
      <AllOf>
        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
          <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">alice</AttributeValue>
          <AttributeDesignator AttributeId="subject-id" DataType="http://www.w3.org/2001/XMLSchema#string" Category="` + categorySubject + `"/>
        </Match>
        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
          <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">Bash</AttributeValue>
          <AttributeDesignator AttributeId="action-id" DataType="http://www.w3.org/2001/XMLSchema#string" Category="` + categoryAction + `"/>
        </Match>
      </AllOf>
    </AnyOf>
    <AnyOf>
      <AllOf>
        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
          <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">alice</AttributeValue>
          <AttributeDesignator AttributeId="subject-id" DataType="http://www.w3.org/2001/XMLSchema#string" Category="` + categorySubject + `"/>
        </Match>
      </AllOf>
    </AnyOf>
  </Target>
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`
	set := prepareOne(t, text)

	// Positive control: alice+Bash satisfies BOTH AnyOf branches (the
	// first's full two-Match conjunction, and the second) — the Target
	// must match. Without this, the negative case below could not be told
	// apart from the Target degrading to always-false.
	t.Run("request satisfying every AnyOf branch matches", func(t *testing.T) {
		in := policy.EvaluationInput{Principal: authz.Principal{Subject: "alice"}, Action: authz.Action{Tool: "Bash"}}
		verdicts := evaluate(t, set, in)
		if len(verdicts) != 1 || verdicts[0].Effect != authz.EffectAllow {
			t.Fatalf("got %+v, want exactly one EffectAllow verdict (alice+Bash satisfies every AnyOf branch)", verdicts)
		}
	})

	// alice+Read satisfies only the second AnyOf branch (subject-id=alice)
	// — the first requires action-id=Bash too, which Read does not
	// satisfy. Under the pre-fix OR-across-AnyOf bug this matched via the
	// second branch alone; §5.5 requires every AnyOf to match, so this must
	// be No Match.
	t.Run("request satisfying only one AnyOf branch does not match (XACML 3.0 §5.5, §7.7 Table 4)", func(t *testing.T) {
		in := policy.EvaluationInput{Principal: authz.Principal{Subject: "alice"}, Action: authz.Action{Tool: "Read"}}
		verdicts := evaluate(t, set, in)
		if len(verdicts) != 0 {
			t.Fatalf("got %+v, want zero verdicts — alice+Read satisfies only the second AnyOf branch, and every AnyOf must match", verdicts)
		}
	})
}

// twoAnyOfTarget builds a <Target> in the canonical one-AnyOf-per-category
// shape a XACML 3.0 author writes for "principal AND action, both
// constrained": one AnyOf pinning subject-id, a second pinning action-id.
// Shared by both cases in
// TestEvaluate_TargetConjunctionFailOpenRegression below, at Policy level
// and at Rule level.
func twoAnyOfTarget(subjectWant, actionWant string) string {
	return `<Target>
    <AnyOf>
      <AllOf>
        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
          <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">` + subjectWant + `</AttributeValue>
          <AttributeDesignator AttributeId="subject-id" DataType="http://www.w3.org/2001/XMLSchema#string" Category="` + categorySubject + `"/>
        </Match>
      </AllOf>
    </AnyOf>
    <AnyOf>
      <AllOf>
        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
          <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">` + actionWant + `</AttributeValue>
          <AttributeDesignator AttributeId="action-id" DataType="http://www.w3.org/2001/XMLSchema#string" Category="` + categoryAction + `"/>
        </Match>
      </AllOf>
    </AnyOf>
  </Target>`
}

// TestEvaluate_TargetConjunctionFailOpenRegression pins the two concrete
// fail-open/over-deny scenarios review found live in the pre-fix
// OR-across-AnyOf (*xmlTarget).evaluate, both built from twoAnyOfTarget's
// canonical shape: a request that satisfies only ONE of the two AnyOf
// branches used to be treated as a Match — XACML 3.0 §5.5 ("conjunctive
// sequence of <AnyOf> elements") and §7.7 Table 4 ("No Match if at least
// one <AnyOf> is No Match") both require every AnyOf to match, so each
// single-branch case below must produce zero verdicts. Checked at both
// Policy level and Rule level: the bug was identical at both, since both
// call through the same (*xmlTarget).evaluate.
func TestEvaluate_TargetConjunctionFailOpenRegression(t *testing.T) {
	// Policy-level Target = AnyOf(subject-id=alice) + AnyOf(action-id=Read)
	// wrapping an unconditional Permit rule — meaning "alice, and only for
	// Read."
	t.Run("policy-level Target", func(t *testing.T) {
		text := `<Policy PolicyId="p1" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  ` + twoAnyOfTarget("alice", "Read") + `
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`
		set := prepareOne(t, text)

		t.Run("alice+Read satisfies both branches: ALLOW", func(t *testing.T) {
			verdicts := evaluate(t, set, policy.EvaluationInput{Principal: authz.Principal{Subject: "alice"}, Action: authz.Action{Tool: "Read"}})
			if len(verdicts) != 1 || verdicts[0].Effect != authz.EffectAllow {
				t.Fatalf("got %+v, want exactly one EffectAllow verdict", verdicts)
			}
		})

		t.Run("bob+Read: right action, wrong subject — No Match, not ALLOW (used to fail open)", func(t *testing.T) {
			verdicts := evaluate(t, set, policy.EvaluationInput{Principal: authz.Principal{Subject: "bob"}, Action: authz.Action{Tool: "Read"}})
			if len(verdicts) != 0 {
				t.Fatalf("got %+v, want zero verdicts — bob does not satisfy the subject-id AnyOf branch", verdicts)
			}
		})

		t.Run("alice+Bash: right subject, wrong action — No Match, not ALLOW (used to fail open)", func(t *testing.T) {
			verdicts := evaluate(t, set, policy.EvaluationInput{Principal: authz.Principal{Subject: "alice"}, Action: authz.Action{Tool: "Bash"}})
			if len(verdicts) != 0 {
				t.Fatalf("got %+v, want zero verdicts — Bash does not satisfy the action-id AnyOf branch", verdicts)
			}
		})
	})

	// Rule-level Target = AnyOf(subject-id=alice) + AnyOf(action-id=Bash)
	// on a Deny rule — the same shape, one level down.
	t.Run("rule-level Target", func(t *testing.T) {
		text := `<Policy PolicyId="p1" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Rule RuleId="r1" Effect="Deny">
    ` + twoAnyOfTarget("alice", "Bash") + `
  </Rule>
</Policy>`
		set := prepareOne(t, text)

		t.Run("alice+Bash satisfies both branches: DENY", func(t *testing.T) {
			verdicts := evaluate(t, set, policy.EvaluationInput{Principal: authz.Principal{Subject: "alice"}, Action: authz.Action{Tool: "Bash"}})
			if len(verdicts) != 1 || verdicts[0].Effect != authz.EffectDeny {
				t.Fatalf("got %+v, want exactly one EffectDeny verdict", verdicts)
			}
		})

		t.Run("alice+Read: right subject, wrong action — No Match, not DENY (used to over-deny)", func(t *testing.T) {
			verdicts := evaluate(t, set, policy.EvaluationInput{Principal: authz.Principal{Subject: "alice"}, Action: authz.Action{Tool: "Read"}})
			if len(verdicts) != 0 {
				t.Fatalf("got %+v, want zero verdicts — Read does not satisfy the action-id AnyOf branch", verdicts)
			}
		})
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
			text := matchDoc(wantMatchID, wantDataType, wantDataType, tc.attributeID, categoryFor(tc.attributeID))
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
