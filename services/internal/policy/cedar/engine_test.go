package cedar

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stratiumdata/stratium/internal/authz"
	"github.com/stratiumdata/stratium/internal/policy"
	"github.com/stratiumdata/stratium/internal/policy/policytest"
	"github.com/stratiumdata/stratium/pkg/models"
)

// TestEngine_Contract runs the shared conformance suite every PolicyEngine
// must pass. It does not reimplement any of these checks itself — that is
// exactly the drift policytest.EngineContract exists to prevent.
func TestEngine_Contract(t *testing.T) {
	policytest.EngineContract(t, New(), policytest.Fixtures{
		Malformed:  "permit(principal, action, resource) when { unbalanced ][",
		WellFormed: "permit(principal, action, resource);",
		AllowAll:   "permit(principal, action, resource);",
		DenyAll:    "forbid(principal, action, resource);",
		DeadForms:  deadForms(),
	})
}

// deadFormReferenceInput is the one EvaluationInput every DeadForm.Live text
// below is written against — deliberately the same reference values named
// in the task 2 brief (trust_tier=CERTIFIED, derived_tier=DESTRUCTIVE,
// purpose=quarterly-close, a resource carrying id and classification), so
// the fixtures below and the brief's own worked examples describe the same
// request throughout.
var deadFormReferenceInput = policy.EvaluationInput{
	Principal:   authz.Principal{Subject: "alice"},
	Agent:       authz.AgentInfo{TrustTier: models.TrustTierCertified},
	DerivedTier: models.ActionTierDestructive,
	Delegation: policy.DelegationContext{
		Purpose: "quarterly-close",
		// Deliberately not EXTERNAL_COMMS by coincidence with DerivedTier's
		// own DESTRUCTIVE: distinct tiers on distinct fields, the same
		// reasoning policytest's own probeInputs doc comment gives for why
		// its probe fields are never accidentally equal to one another —
		// two fields sharing a value can mask one being read in place of
		// the other.
		MaxActionTier: models.ActionTierExternalComms,
	},
	Resource: map[string]string{"id": "res-1", "classification": "restricted"},
}

// deadFormUnlessLiveInput is the LiveInput for every "unless:"-prefixed
// entry below — the fix for the whole-branch review's Critical finding: a
// dead (always-false) conjunct inside an "unless" body used to be silently
// accepted as a harmless no-op, when it actually deletes the enclosing
// policy's own exception (see deadform.go's package doc, "Why only through
// &&, for either clause kind"). Unlike deadFormReferenceInput — chosen so a
// WHEN clause's live condition MATCHES it — an unless clause's Live form
// must NOT have its exception triggered by LiveInput: an unless-guarded
// permit whose exception fires produces zero verdicts for that policy
// alone, which would fail testDeadForms' own "live text ... produces a
// verdict" check (policytest/contract.go) for a reason unrelated to
// whether Dead was rejected. TrustTier and DerivedTier are therefore held
// well clear of every value the "unless:" dead forms below spell wrong, so
// each Live counterpart's real (correctly-spelled) exception does not
// apply and the base permit matches normally.
var deadFormUnlessLiveInput = policy.EvaluationInput{
	Principal:   authz.Principal{Subject: "alice"},
	Agent:       authz.AgentInfo{TrustTier: models.TrustTierUnverified},
	DerivedTier: models.ActionTierReasoning,
}

// deadFormContextKindReferenceInput is the LiveInput for the four
// "context field kind:" entries below — the fix for the whole-branch
// review's Important finding that knownTierVocabulary's two paths were the
// only context fields checked for a mismatched comparison, leaving every
// Boolean, Long, and Set field silently dead against a wrong-kind literal
// (see deadform.go's contextFieldKind). Chosen so each field's Live
// (correctly-typed) comparison actually matches, proving the fix produces
// a real verdict rather than merely accepting the text.
var deadFormContextKindReferenceInput = policy.EvaluationInput{
	Principal: authz.Principal{Subject: "alice"},
	Agent: authz.AgentInfo{
		Suspended:    true,
		Enabled:      false,
		AllowedTools: []string{"Bash"},
	},
	Delegation: policy.DelegationContext{Depth: 2},
}

// deadFormActionScopeLiveInput is the LiveInput for the two action-scope
// entries below — the fix for the whole-branch review's Important finding
// that checkScopeEntityType was only ever called for the principal and
// resource slots, never action, so `action == Widget::"Bash"` and
// `action == User::"Bash"` both validated, prepared, and could never
// match. Action.Tool is the only field buildRequest reads to build the
// action entity (request.go's buildRequest).
var deadFormActionScopeLiveInput = policy.EvaluationInput{
	Principal: authz.Principal{Subject: "alice"},
	Action:    authz.Action{Tool: "Bash"},
}

// deadForms is every dead shape this package rejects at authoring time.
// The original nine are Task 2's — see deadform.go's package doc for why
// those nine (of the thirteen the task 2 brief audited) needed new checks,
// and the task report for the full classification of all thirteen. Every
// Dead text below is verified (in deadform_test.go, and empirically before
// each was added) to have validated, prepared, and produced zero verdicts
// against its own LiveInput before its fix landed; every Live text is its
// minimal correction, differing only in the one respect its own dead form
// is named for — except "unless: contradiction," whose Dead form (1 == 2)
// has no request-dependent path to correct in place: the minimal live
// counterpart is a real, request-dependent condition instead of a
// same-shape literal edit (see deadFormUnlessLiveInput's own doc comment
// for why 1 == 1, the when-side fixture's own trick, does not work here).
//
// The three groups appended after the original nine are the whole-branch
// review's own three findings, all three the same class the review named
// them as (see this package's own doc comment): "unless:" (Critical: dead
// forms silently widened rather than killed a policy when the enclosing
// clause was "unless" instead of "when"), "context field kind:" (Important:
// knownTierVocabulary's two paths left every other closed-kind context
// field uncovered), and the two action-scope entries (Important:
// checkScopeEntityType was never called for the action slot).
func deadForms() []policytest.DeadForm {
	return []policytest.DeadForm{
		{
			Name:      "wrong-case enum",
			Dead:      `permit(principal, action, resource) when { context.agent.trust_tier == "Certified" };`,
			Live:      `permit(principal, action, resource) when { context.agent.trust_tier == "CERTIFIED" };`,
			LiveInput: deadFormReferenceInput,
		},
		{
			Name: "ordinal instead of name",
			// A rule ported from Rego, where derived_tier's own comparisons
			// use the bare ordinal — see rego/engine.go's package doc — but
			// trust_tier stays a String on both sides of this port, never an
			// ordinal Long; "2" is CERTIFIED's ordinal (models.tier.go), not
			// its name.
			Dead:      `permit(principal, action, resource) when { context.agent.trust_tier == "2" };`,
			Live:      `permit(principal, action, resource) when { context.agent.trust_tier == "CERTIFIED" };`,
			LiveInput: deadFormReferenceInput,
		},
		{
			Name:      "padded literal",
			Dead:      `permit(principal, action, resource) when { context.agent.trust_tier == " CERTIFIED " };`,
			Live:      `permit(principal, action, resource) when { context.agent.trust_tier == "CERTIFIED" };`,
			LiveInput: deadFormReferenceInput,
		},
		{
			Name: "name instead of ordinal",
			// The mirror image of "ordinal instead of name": a rule ported
			// from XACML, which spells every tier by name (see
			// xacml/schema.go's actionTierValues) — but derived_tier is a
			// Cedar Long here (request.go's buildRequest), never a String.
			Dead:      `permit(principal, action, resource) when { context.derived_tier == "DESTRUCTIVE" };`,
			Live:      fmt.Sprintf(`permit(principal, action, resource) when { context.derived_tier == %d };`, int(models.ActionTierDestructive)),
			LiveInput: deadFormReferenceInput,
		},
		{
			Name:      "out-of-lattice ceiling",
			Dead:      `permit(principal, action, resource) when { context.derived_tier > 99 };`,
			Live:      fmt.Sprintf(`permit(principal, action, resource) when { context.derived_tier >= %d };`, int(models.ActionTierDestructive)),
			LiveInput: deadFormReferenceInput,
		},
		{
			Name:      "unknown entity type",
			Dead:      `permit(principal == Usr::"alice", action, resource);`,
			Live:      `permit(principal == User::"alice", action, resource);`,
			LiveInput: deadFormReferenceInput,
		},
		{
			Name:      "wrong principal type",
			Dead:      `permit(principal is Resource, action, resource);`,
			Live:      `permit(principal is User, action, resource);`,
			LiveInput: deadFormReferenceInput,
		},
		{
			Name:      "contradiction",
			Dead:      `permit(principal, action, resource) when { 1 == 2 };`,
			Live:      `permit(principal, action, resource) when { 1 == 1 };`,
			LiveInput: deadFormReferenceInput,
		},
		{
			Name: "vacuous empty set",
			// Cedar's scope grammar rejects an empty entity list outright
			// (principal in [] does not even parse — confirmed empirically),
			// so the form that actually reaches Prepare unrejected today is
			// an empty Set.contains(...) call, the idiom an author reaching
			// for "is this tier one of these" would actually write (Cedar's
			// `in` operator itself only tests entity-hierarchy membership,
			// not generic set membership — see the task report).
			Dead:      `permit(principal, action, resource) when { [].contains(context.agent.trust_tier) };`,
			Live:      `permit(principal, action, resource) when { ["CERTIFIED", "PLATFORM_TRUSTED"].contains(context.agent.trust_tier) };`,
			LiveInput: deadFormReferenceInput,
		},

		// --- Critical: dead forms inside "unless" widened instead of
		// killed a policy (deadform.go's checkDeadForms used to skip every
		// "unless" clause body entirely). Each of these six mirrors one of
		// the nine "when:" forms above, wrapped in "unless" instead —
		// verified against the real engine, pre-fix: every one of them
		// validated, prepared, and folded to ALLOW for a CERTIFIED /
		// DESTRUCTIVE agent that a correctly-spelled exception would have
		// denied (see deadFormUnlessLiveInput's own doc comment).
		{
			Name:      "unless: wrong-case enum",
			Dead:      `permit(principal, action, resource) unless { context.agent.trust_tier == "Certified" };`,
			Live:      `permit(principal, action, resource) unless { context.agent.trust_tier == "CERTIFIED" };`,
			LiveInput: deadFormUnlessLiveInput,
		},
		{
			Name:      "unless: ordinal instead of name",
			Dead:      `permit(principal, action, resource) unless { context.agent.trust_tier == "2" };`,
			Live:      `permit(principal, action, resource) unless { context.agent.trust_tier == "CERTIFIED" };`,
			LiveInput: deadFormUnlessLiveInput,
		},
		{
			Name:      "unless: padded literal",
			Dead:      `permit(principal, action, resource) unless { context.agent.trust_tier == " CERTIFIED " };`,
			Live:      `permit(principal, action, resource) unless { context.agent.trust_tier == "CERTIFIED" };`,
			LiveInput: deadFormUnlessLiveInput,
		},
		{
			Name: "unless: contradiction",
			// Live is NOT "unless { 1 == 1 }" — the when-side "contradiction"
			// entry's own trick. Flipping a contradiction to a tautology
			// inside an unless body makes the clause's own requirement (!Y)
			// impossible instead of vacuous: still dead, just in the
			// opposite direction (see deadform.go's package doc). Only a
			// real, request-dependent condition actually narrows.
			Dead:      `permit(principal, action, resource) unless { 1 == 2 };`,
			Live:      `permit(principal, action, resource) unless { context.agent.trust_tier == "CERTIFIED" };`,
			LiveInput: deadFormUnlessLiveInput,
		},
		{
			Name:      "unless: name instead of ordinal",
			Dead:      `permit(principal, action, resource) unless { context.derived_tier == "DESTRUCTIVE" };`,
			Live:      fmt.Sprintf(`permit(principal, action, resource) unless { context.derived_tier == %d };`, int(models.ActionTierDestructive)),
			LiveInput: deadFormUnlessLiveInput,
		},
		{
			Name:      "unless: out-of-lattice ceiling",
			Dead:      `permit(principal, action, resource) unless { context.derived_tier > 99 };`,
			Live:      fmt.Sprintf(`permit(principal, action, resource) unless { context.derived_tier >= %d };`, int(models.ActionTierDestructive)),
			LiveInput: deadFormUnlessLiveInput,
		},

		// --- Important: knownTierVocabulary's two paths were the only
		// context fields checked for a mismatched comparison — every other
		// closed-kind field (Boolean, Long, Set) was silently dead against
		// a wrong-kind literal. The first two below are a second gap found
		// while fixing the first: trust_tier and max_action_tier are
		// STRING-vocabulary-checked by knownTierVocabulary already, but a
		// non-string literal against either one was never checked at all
		// (an earlier version of this file assumed, wrongly, that it was
		// already a loud evaluation-time error — see checkTierVocabulary's
		// own doc comment).
		{
			Name:      "context field kind: trust_tier vs non-string",
			Dead:      `forbid(principal, action, resource) when { context.agent.trust_tier == 5 };`,
			Live:      `forbid(principal, action, resource) when { context.agent.trust_tier == "CERTIFIED" };`,
			LiveInput: deadFormReferenceInput,
		},
		{
			Name: "context field kind: max_action_tier vs non-string",
			Dead: `forbid(principal, action, resource) when { context.delegation.max_action_tier == 3 };`,
			Live: fmt.Sprintf(`forbid(principal, action, resource) when { context.delegation.max_action_tier == %q };`,
				models.ActionTierExternalComms.String()),
			LiveInput: deadFormReferenceInput,
		},
		{
			Name:      "context field kind: suspended vs string",
			Dead:      `forbid(principal, action, resource) when { context.agent.suspended == "true" };`,
			Live:      `forbid(principal, action, resource) when { context.agent.suspended == true };`,
			LiveInput: deadFormContextKindReferenceInput,
		},
		{
			Name:      "context field kind: enabled vs string",
			Dead:      `forbid(principal, action, resource) when { context.agent.enabled == "false" };`,
			Live:      `forbid(principal, action, resource) when { context.agent.enabled == false };`,
			LiveInput: deadFormContextKindReferenceInput,
		},
		{
			Name:      "context field kind: depth vs string",
			Dead:      `forbid(principal, action, resource) when { context.delegation.depth == "2" };`,
			Live:      `forbid(principal, action, resource) when { context.delegation.depth == 2 };`,
			LiveInput: deadFormContextKindReferenceInput,
		},
		{
			Name: "context field kind: allowed_tools vs string",
			// A Set has no scalar spelling that could ever satisfy "==" —
			// the minimal correction changes the comparison shape itself,
			// not just the literal's kind, to Cedar's actual membership
			// test.
			Dead:      `forbid(principal, action, resource) when { context.agent.allowed_tools == "Bash" };`,
			Live:      `forbid(principal, action, resource) when { context.agent.allowed_tools.contains("Bash") };`,
			LiveInput: deadFormContextKindReferenceInput,
		},

		// --- Important: checkScopeEntityType was called for principal and
		// resource but never action, so a scope naming the wrong entity
		// type in the action slot validated, prepared, and could never
		// match — the same defect "unknown entity type" and "wrong
		// principal type" above already cover for principal.
		{
			Name:      "unknown action entity type",
			Dead:      `permit(principal, action == Widget::"Bash", resource);`,
			Live:      `permit(principal, action == Action::"Bash", resource);`,
			LiveInput: deadFormActionScopeLiveInput,
		},
		{
			Name:      "wrong action entity type",
			Dead:      `permit(principal, action == User::"Bash", resource);`,
			Live:      `permit(principal, action == Action::"Bash", resource);`,
			LiveInput: deadFormActionScopeLiveInput,
		},
	}
}

// TestPrepare_MalformedPolicyErrorNamesTheOffenderByName covers what
// policytest.EngineContract's "prepare on malformed text fails and names
// the offending policy's ID" property does not: Cedar's error already names
// the offender by ID there, checked engine-independently against every
// engine. This test is only for the Name half, which is Cedar's own
// formatting choice (see Prepare's fmt.Errorf call site, which interpolates
// sp.Name alongside sp.ID) — a courtesy to an operator who recognizes
// policies by name, not a promise every future engine must keep.
func TestPrepare_MalformedPolicyErrorNamesTheOffenderByName(t *testing.T) {
	ctx := context.Background()
	policies := []policy.StoredPolicy{
		{ID: "good-1", Name: "always-permit", Text: "permit(principal, action, resource);"},
		{ID: "bad-owner-7", Name: "quarantine-rule", Text: "permit(principal, action, resource) when { unbalanced ]["},
	}

	_, err := New().Prepare(ctx, policies)
	if err == nil {
		t.Fatal("Prepare accepted a malformed policy, want an error")
	}
	if !strings.Contains(err.Error(), "quarantine-rule") {
		t.Errorf("error does not name the offending policy's name: %v", err)
	}
	// And it must not, say, blame the well-formed policy that happens to
	// share the same Prepare call.
	if strings.Contains(err.Error(), "always-permit") {
		t.Errorf("error blames the well-formed policy's name instead of the malformed one's: %v", err)
	}
}

func TestPrepare_RejectsTextWithoutExactlyOneStatement(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		text string
	}{
		{"empty text", ""},
		{"two statements", "permit(principal, action, resource);\nforbid(principal, action, resource);"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policies := []policy.StoredPolicy{{ID: "p1", Name: "multi", Text: tc.text}}
			if _, err := New().Prepare(ctx, policies); err == nil {
				t.Fatalf("Prepare accepted text with != 1 statement (%q), want an error", tc.text)
			}
		})
	}
}

// TestValidate_MirrorsPrepareOnMalformedText used to check that Cedar's
// Validate and Prepare treat the same malformed text the same way. Both
// halves of that claim are now proven by policytest.EngineContract, which
// runs "unbalanced ][" (this test's own fixture, verbatim) through both
// Validate ("validate" property) and Prepare ("prepare on malformed text"
// property) already — this test would only be checking the same input
// against the same two code paths a second time.

// sensitiveCedarCalls are this package's spec-defect-D5-relevant operations:
// parsing policy text, and (since Task 2) walking a parsed policy for dead
// forms. Both must happen only once per policy, at Prepare or Validate time
// — never per Evaluate call, or every decision repeats work (parsing,
// JSON re-serialization, dead-form analysis) that changes nothing about the
// policy set that already-compiled it once. See
// TestParseAndDeadFormChecksOnlyReachableFromPrepareOrValidate's own doc
// comment for why this is a reachability check, not the simpler direct-
// caller scan rego/engine_test.go's equivalent guard uses.
var sensitiveCedarCalls = []string{"NewPolicyListFromBytes", "checkDeadForms"}

// allowedEntryPoints are the only functions permitted to (transitively)
// reach a sensitiveCedarCalls target: Prepare, the compile-once step;
// Validate, the PAP's authoring-time check, which compiles and analyses
// text the same way but is never called on a per-decision path; and
// DeclaredEffect, internal/store's own write-time effect-agreement check
// (policy.go's validateEffectAgreement) — a third authoring-time-only
// caller, never reachable from Evaluate either, that parses text via the
// identical parseOne this package already trusts Prepare/Validate to call
// for the same reason.
var allowedEntryPoints = map[string]bool{
	"Prepare":        true,
	"Validate":       true,
	"DeclaredEffect": true,
}

// buildCallGraph parses every non-test .go file in this package and returns
// callers: for each function or method name, the set of names (also by bare
// identifier, ignoring receiver type and package qualification — sufficient
// here because this package defines exactly one function or method per name
// used below) that directly call it anywhere in their body.
func buildCallGraph(t *testing.T) map[string][]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("listing package source: %v", err)
	}

	fset := token.NewFileSet()
	callers := map[string][]string{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			for _, callee := range calleeNames(fn.Body) {
				callers[callee] = append(callers[callee], fn.Name.Name)
			}
		}
	}
	return callers
}

// calleeNames returns the bare name of every function or method called
// anywhere within node, whether reached through a selector
// (x.NewPolicyListFromBytes(...), pkg.NewPolicyListFromBytes(...)) or a bare
// identifier (checkDeadForms(...)) — the same dual form
// rego/engine_test.go's prepareForEvalCallCount already handles, generalized
// here to collect every distinct callee name instead of counting one fixed
// name.
func calleeNames(node ast.Node) []string {
	var names []string
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			names = append(names, fun.Sel.Name)
		case *ast.Ident:
			names = append(names, fun.Name)
		}
		return true
	})
	return names
}

// unauthorizedRoots walks callers backward from target — "who calls the
// thing that calls the thing that calls target" — stopping each branch the
// moment it reaches a name in allowed (that branch is fine: the sensitive
// call only happens because Prepare or Validate chose to make it). A name
// with no recorded caller at all (a "root" in this graph — every exported
// method is one, since nothing in this package calls its own public API)
// that is reached this way and is NOT in allowed is reported: that is a
// path from outside {Prepare, Validate} straight to target, whether direct
// or through any number of intermediate helpers.
func unauthorizedRoots(target string, callers map[string][]string, allowed map[string]bool) []string {
	var bad []string
	visited := map[string]bool{}
	var walk func(name string)
	walk = func(name string) {
		if allowed[name] || visited[name] {
			return
		}
		visited[name] = true
		callersOfName := callers[name]
		if len(callersOfName) == 0 {
			bad = append(bad, name)
			return
		}
		for _, c := range callersOfName {
			walk(c)
		}
	}
	for _, c := range callers[target] {
		walk(c)
	}
	return bad
}

// TestParseAndDeadFormChecksOnlyReachableFromPrepareOrValidate guards spec
// defect D5 for Cedar — see rego/engine_test.go's
// TestPrepareForEval_OnlyCalledFromPrepareOrValidate for the full defect
// description; this is that same guard, adapted for a wrinkle Cedar has and
// Rego does not.
//
// A direct scan for calls to cedarlib.NewPolicyListFromBytes — mirroring
// rego's guard structurally — is not sufficient here: unlike rego, which
// calls PrepareForEval straight from both Prepare and Validate, this
// package routes every parse through parseOne, a shared helper that exists
// so the "expect exactly one policy statement" rule cannot drift between
// the two call sites (see parseOne's own doc comment). A scan that only
// recognizes the literal library call would find it inside parseOne — a
// function named neither "Prepare" nor "Validate" — and would either false-
// positive against this package's own correct code today, or, worse, miss
// a future regression entirely: if Evaluate were ever changed to call
// parseOne directly (reintroducing D5 without ever writing the words
// "NewPolicyListFromBytes" inside Evaluate itself), a same-shaped direct-
// caller scan would still see NewPolicyListFromBytes's only caller as
// parseOne, exactly as it does today, and report nothing wrong. This is the
// trap a Phase 4 task hit, named directly in this task's own brief.
//
// unauthorizedRoots closes that gap by walking the call graph BACKWARD from
// each sensitive target, through any number of intermediate helpers,
// stopping only at Prepare or Validate — so parseOne (and checkDeadForms,
// this task's own second sensitive operation) are correctly treated as
// "parse-shaped" without needing to name them as a special case: the walk
// discovers the indirection from the graph itself, and would discover a
// *new* helper introduced tomorrow the same way.
func TestParseAndDeadFormChecksOnlyReachableFromPrepareOrValidate(t *testing.T) {
	callers := buildCallGraph(t)

	totalDirectCallSites := 0
	for _, target := range sensitiveCedarCalls {
		direct := callers[target]
		totalDirectCallSites += len(direct)

		if bad := unauthorizedRoots(target, callers, allowedEntryPoints); len(bad) > 0 {
			t.Errorf("%s is reachable from %v without passing through Prepare or Validate — a call from here re-parses or re-analyses a policy on every decision instead of once at Prepare time (spec defect D5); direct callers: %v",
				target, bad, direct)
		}
	}

	// Positive control, the same shape as rego's own: if the scan found no
	// call sites for either sensitive name at all, both checks above pass
	// vacuously regardless of what Evaluate does — a renamed function
	// (parseOne, checkDeadForms, NewPolicyListFromBytes itself) or a wrong
	// glob would silently defeat this test rather than failing it.
	if totalDirectCallSites == 0 {
		t.Fatal("found zero call sites for either sensitive operation anywhere in this package — the guard isn't exercising anything, fix the scan")
	}
}
