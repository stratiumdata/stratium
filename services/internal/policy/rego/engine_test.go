package rego

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"stratium/internal/authz"
	"stratium/internal/policy"
	"stratium/internal/policy/policytest"
	"stratium/pkg/models"
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
		DeadForms: []policytest.DeadForm{
			{
				// Same fixture TestPrepare_RejectsWrongPackage and
				// TestValidate_RejectsWrongPackage already exercise directly
				// below — reused here, not retranscribed, so the contract-level
				// property and this package's own regression tests can never
				// drift out of sync with each other.
				Name: "wrong package declaration",
				Dead: `package stratium.oops

allow := true`,
				Live: `package stratium.policy

allow := true`,
				LiveInput: policy.EvaluationInput{},
			},
			{
				// The task's own headline example: agent.trust_tier is a
				// string (models.AgentTrustTier.String(), see input.go's
				// agentDoc), so this is not a threshold check on any real
				// ordinal — it is Rego's cross-type total order, always true,
				// an unconditional principal-leg allow regardless of the
				// agent's actual trust tier. Same fixture
				// TestPrepare_RejectsMismatchedTypeComparison and
				// TestValidate_RejectsMismatchedTypeComparison exercise
				// directly below, for the same "never retranscribe" reason as
				// "wrong package declaration" above. Live expresses the
				// closest same-intent correct idiom: Rego exposes no numeric
				// ordinal for trust_tier (see engine.go's package doc), so
				// "at least CERTIFIED" is a set-membership check over the
				// real string vocabulary, not an ordinal comparison.
				Name: "string field compared as an ordinal",
				Dead: `package stratium.policy

allow if {
	input.agent.trust_tier > 2
}`,
				Live: `package stratium.policy

allow if {
	input.agent.trust_tier in {"CERTIFIED", "PLATFORM_TRUSTED"}
}`,
				LiveInput: policy.EvaluationInput{
					Agent: authz.AgentInfo{TrustTier: models.TrustTierCertified},
				},
			},
			{
				// The task's other headline example: derived_tier is mapped
				// as a JSON number specifically so ordinal comparisons work
				// (see engine.go's package doc) — quoting the literal defeats
				// that, and, symmetrically to the case above, is always true
				// regardless of the real derived tier. Live is the minimal
				// correction: the same field, the same threshold, the
				// literal's quotes removed.
				Name: "ordinal field compared as a string",
				Dead: `package stratium.policy

allow if {
	input.derived_tier <= "2"
}`,
				Live: `package stratium.policy

allow if {
	input.derived_tier <= 2
}`,
				LiveInput: policy.EvaluationInput{
					DerivedTier: models.ActionTierInternalModify,
				},
			},
			{
				// Found in review after the first two entries above shipped:
				// != has the identical gap (see comparisonOperators' own doc
				// comment in schema.go) — a string can never structurally
				// equal a number, so != between them is unconditionally true,
				// the same unconditional-allow shape as "string field
				// compared as an ordinal" above, reached through a different
				// builtin. Same fixture
				// TestPrepare_RejectsMismatchedTypeComparison and
				// TestValidate_RejectsMismatchedTypeComparison exercise
				// directly below. Live restates the same field with the real
				// string vocabulary: "allow anyone whose agent is not
				// UNVERIFIED" is a real, useful policy; the dead form's "!= 2"
				// never was.
				Name: "string field compared for inequality against a number",
				Dead: `package stratium.policy

allow if {
	input.agent.trust_tier != 2
}`,
				Live: `package stratium.policy

allow if {
	input.agent.trust_tier != "UNVERIFIED"
}`,
				LiveInput: policy.EvaluationInput{
					Agent: authz.AgentInfo{TrustTier: models.TrustTierCertified},
				},
			},
		},
	})
}

// TestPrepare_RejectsWrongPackage guards the fix for a review-found Critical:
// rego.New(...).PrepareForEval accepts a module declaring any package, and
// this engine only ever queries queryPath (data.stratium.policy) — so a
// policy whose module declared, say, `package stratium.oops` used to
// compile cleanly and then never produce a verdict for any input, forever,
// with nothing at Prepare time or decision time distinguishing it from a
// rule that correctly never fires. See checkPackage's own doc comment for
// the full reasoning and why a runtime probe cannot substitute for this
// static check. Names the offending policy's ID, the same property
// policytest.EngineContract's own "malformed" case checks for other kinds
// of bad text.
func TestPrepare_RejectsWrongPackage(t *testing.T) {
	t.Run("wrong package is rejected, naming the policy ID", func(t *testing.T) {
		const wantID = "wrong-package-under-test"
		_, err := New().Prepare(context.Background(), []policy.StoredPolicy{
			{ID: wantID, Name: "typo'd package", Text: `package stratium.oops

allow := true`},
		})
		if err == nil {
			t.Fatal("Prepare accepted a policy declaring the wrong package, want an error")
		}
		if !strings.Contains(err.Error(), wantID) {
			t.Errorf("error does not name the offending policy's ID %q: %v", wantID, err)
		}
	})

	// Positive control: the check above must reject the wrong package
	// specifically, not policies in general — otherwise this "fix" would be
	// indistinguishable from Prepare rejecting everything.
	t.Run("correct package still prepares normally", func(t *testing.T) {
		_, err := New().Prepare(context.Background(), []policy.StoredPolicy{
			{ID: "right-package-under-test", Name: "correct", Text: `package stratium.policy

allow := true`},
		})
		if err != nil {
			t.Fatalf("Prepare rejected a correctly-packaged policy: %v", err)
		}
	})
}

// TestValidate_RejectsWrongPackage is TestPrepare_RejectsWrongPackage's
// counterpart for the PAP's authoring-time gate — deliberately a separate
// test function, not a subtest folded into the one above, because the fix
// touches Prepare and Validate independently (checkPackage is called from
// both, but each call site can regress on its own) and a single test
// covering both call sites would leave whichever one broke first still
// green.
func TestValidate_RejectsWrongPackage(t *testing.T) {
	t.Run("wrong package is rejected", func(t *testing.T) {
		err := New().Validate(context.Background(), `package stratium.oops

allow := true`)
		if err == nil {
			t.Fatal("Validate accepted text declaring the wrong package, want an error")
		}
	})

	t.Run("correct package still validates normally", func(t *testing.T) {
		err := New().Validate(context.Background(), `package stratium.policy

allow := true`)
		if err != nil {
			t.Fatalf("Validate rejected correctly-packaged text: %v", err)
		}
	})
}

// mismatchedComparisonText, mismatchedOrdinalText, and mismatchedNeqText are
// the same three Dead fixtures policytest.EngineContract's DeadForms
// exercises indirectly (engine_test.go's TestEngine_Contract) — reused
// verbatim here, not retranscribed, for the identical reason
// TestPrepare_RejectsWrongPackage's own comment gives for its wrong-package
// fixture: this package's own regression tests and the contract-level
// property must never be able to drift out of sync with each other.
const (
	mismatchedComparisonText = `package stratium.policy

allow if {
	input.agent.trust_tier > 2
}`
	mismatchedOrdinalText = `package stratium.policy

allow if {
	input.derived_tier <= "2"
}`
	// mismatchedNeqText is comparisonOperators' follow-up entry (see
	// schema.go): a string field compared for inequality against a number is
	// unconditionally true, the same unconditional-allow shape as
	// mismatchedComparisonText, reached through neq instead of gt.
	mismatchedNeqText = `package stratium.policy

allow if {
	input.agent.trust_tier != 2
}`
	// mismatchedEqualityText exercises inputSchemaSet's own contribution in
	// isolation from checkComparisonTypes: == compiles to Rego's "equal"
	// builtin, which OPA's schema-driven type check DOES catch on its own
	// (confirmed empirically — see schema.go's package comment), unlike
	// gt/gte/lt/lte/neq. Without a fixture that only the schema, and not
	// checkComparisonTypes, can reject, removing regolib.Schemas(...)
	// entirely would pass every other test in this file — see
	// TestPrepare_SchemaAloneRejectsMismatchedEquality's own comment.
	mismatchedEqualityText = `package stratium.policy

allow if {
	input.agent.trust_tier == 2
}`
)

// TestPrepare_RejectsMismatchedTypeComparison is this task's central
// regression guard: without checkComparisonTypes, both fixtures below
// compile cleanly (confirmed before this fix existed) and, evaluated against
// an UNVERIFIED agent or a DESTRUCTIVE derived tier respectively, produce an
// unconditional allow — the one finding in the phase-wide review where a
// wrong policy widens instead of going inert. Mirrors
// TestPrepare_RejectsWrongPackage's shape exactly, including the positive
// control: without it, this "fix" would be indistinguishable from Prepare
// rejecting every comparison.
func TestPrepare_RejectsMismatchedTypeComparison(t *testing.T) {
	t.Run("string field compared as an ordinal (agent.trust_tier > 2) is rejected, naming the policy", func(t *testing.T) {
		const wantID = "mismatched-comparison-under-test"
		_, err := New().Prepare(context.Background(), []policy.StoredPolicy{
			{ID: wantID, Name: "ported-from-cedar", Text: mismatchedComparisonText},
		})
		if err == nil {
			t.Fatal("Prepare accepted input.agent.trust_tier > 2, want an error (trust_tier is a string; this compiles to an unconditional allow)")
		}
		if !strings.Contains(err.Error(), wantID) {
			t.Errorf("error does not name the offending policy's ID %q: %v", wantID, err)
		}
	})

	t.Run("numeric field compared as a string (derived_tier <= \"2\") is rejected, naming the policy", func(t *testing.T) {
		const wantID = "mismatched-ordinal-under-test"
		_, err := New().Prepare(context.Background(), []policy.StoredPolicy{
			{ID: wantID, Name: "quoted-literal", Text: mismatchedOrdinalText},
		})
		if err == nil {
			t.Fatal(`Prepare accepted input.derived_tier <= "2", want an error (derived_tier is a number; this compiles to an unconditional allow)`)
		}
		if !strings.Contains(err.Error(), wantID) {
			t.Errorf("error does not name the offending policy's ID %q: %v", wantID, err)
		}
	})

	// comparisonOperators' follow-up entry (see schema.go): a string field
	// compared for inequality against a number is unconditionally true the
	// same way > against the wrong field is — reached through neq instead of
	// gt. Mutation target for this follow-up round: removing "neq" from
	// comparisonOperators fails this subtest and its Validate counterpart
	// without touching the gt/lte subtests above, or either "still prepare/
	// validate normally" control below.
	t.Run("string field compared for inequality against a number (agent.trust_tier != 2) is rejected, naming the policy", func(t *testing.T) {
		const wantID = "mismatched-neq-under-test"
		_, err := New().Prepare(context.Background(), []policy.StoredPolicy{
			{ID: wantID, Name: "not-equal-ordinal", Text: mismatchedNeqText},
		})
		if err == nil {
			t.Fatal("Prepare accepted input.agent.trust_tier != 2, want an error (trust_tier is a string; this compiles to an unconditional allow)")
		}
		if !strings.Contains(err.Error(), wantID) {
			t.Errorf("error does not name the offending policy's ID %q: %v", wantID, err)
		}
	})

	// Positive control: correctly-typed ordinal comparisons — same operators,
	// same fields, agreeing types — must keep preparing normally. Without
	// this, the checks above would not be distinguishable from Prepare
	// rejecting every gt/gte/lt/lte comparison outright.
	t.Run("correctly-typed comparisons still prepare normally", func(t *testing.T) {
		_, err := New().Prepare(context.Background(), []policy.StoredPolicy{
			{ID: "same-kind-under-test", Name: "correct", Text: `package stratium.policy

allow if {
	input.derived_tier > 0
	input.derived_tier <= 2
}`},
		})
		if err != nil {
			t.Fatalf("Prepare rejected a correctly-typed numeric comparison: %v", err)
		}
	})

	// The over-rejection control the coordinator asked to weigh heavier than
	// the rejection itself: != is common in legitimately well-typed
	// policies (unlike >/>=/</<=, which rarely appear against a string
	// field at all), so a same-kind != on the identical field the rejection
	// subtest above uses must keep working. Without this, "reject != when
	// the schema says string vs. number" would be indistinguishable from
	// "reject every use of !=."
	t.Run("correctly-typed inequality still prepares normally", func(t *testing.T) {
		_, err := New().Prepare(context.Background(), []policy.StoredPolicy{
			{ID: "same-kind-neq-under-test", Name: "correct", Text: `package stratium.policy

deny if {
	input.agent.trust_tier != "CERTIFIED"
}`},
		})
		if err != nil {
			t.Fatalf("Prepare rejected a correctly-typed inequality comparison: %v", err)
		}
	})

	// checkComparisonExpr only ever rejects a pair it can prove disagree;
	// neither of these operands is provable — a tenant-open map key
	// (resource has no fixed key set, see schema.go's package comment) and a
	// local variable (checkComparisonExpr does no data-flow analysis, so a
	// var bound from input.derived_tier is exactly as "unknown" to it as one
	// bound from anywhere else) — so both must still prepare normally, not
	// be treated as an unprovable kind of mismatch.
	t.Run("inequality against an unknown operand still prepares normally", func(t *testing.T) {
		t.Run("open tenant map key", func(t *testing.T) {
			_, err := New().Prepare(context.Background(), []policy.StoredPolicy{
				{ID: "unknown-neq-resource-under-test", Name: "correct", Text: `package stratium.policy

deny if {
	input.resource.classification != "restricted"
}`},
			})
			if err != nil {
				t.Fatalf("Prepare rejected != against an open tenant-map key: %v", err)
			}
		})

		t.Run("variable", func(t *testing.T) {
			_, err := New().Prepare(context.Background(), []policy.StoredPolicy{
				{ID: "unknown-neq-var-under-test", Name: "correct", Text: `package stratium.policy

deny if {
	tier := input.derived_tier
	tier != 2
}`},
			})
			if err != nil {
				t.Fatalf("Prepare rejected != against a local variable: %v", err)
			}
		})
	})
}

// TestValidate_RejectsMismatchedTypeComparison is
// TestPrepare_RejectsMismatchedTypeComparison's counterpart for the PAP's
// authoring-time gate — deliberately a separate test function, not a
// subtest folded into the one above, for the same reason
// TestValidate_RejectsWrongPackage's own comment gives: checkComparisonTypes
// is called from both Prepare and Validate, but each call site can regress
// on its own, and a single test covering both would leave whichever one
// broke first still green. This is mutation target (a)/(b) from the task
// brief: removing the checkComparisonTypes call from Prepare only fails this
// function's sibling above without touching this one, and vice versa.
func TestValidate_RejectsMismatchedTypeComparison(t *testing.T) {
	t.Run("string field compared as an ordinal is rejected", func(t *testing.T) {
		err := New().Validate(context.Background(), mismatchedComparisonText)
		if err == nil {
			t.Fatal("Validate accepted input.agent.trust_tier > 2, want an error")
		}
	})

	t.Run("numeric field compared as a string is rejected", func(t *testing.T) {
		err := New().Validate(context.Background(), mismatchedOrdinalText)
		if err == nil {
			t.Fatal(`Validate accepted input.derived_tier <= "2", want an error`)
		}
	})

	// Mutation target for this follow-up round, the Validate-side sibling of
	// the identically-named Prepare subtest: removing "neq" from
	// comparisonOperators fails both without touching the gt/lte subtests
	// above.
	t.Run("string field compared for inequality against a number is rejected", func(t *testing.T) {
		err := New().Validate(context.Background(), mismatchedNeqText)
		if err == nil {
			t.Fatal("Validate accepted input.agent.trust_tier != 2, want an error")
		}
	})

	t.Run("correctly-typed comparisons still validate normally", func(t *testing.T) {
		err := New().Validate(context.Background(), `package stratium.policy

allow if {
	input.derived_tier > 0
	input.derived_tier <= 2
}`)
		if err != nil {
			t.Fatalf("Validate rejected a correctly-typed numeric comparison: %v", err)
		}
	})

	// Validate-side over-rejection control — see the Prepare-side subtest's
	// own comment for why this matters more than the rejection above.
	t.Run("correctly-typed inequality still validates normally", func(t *testing.T) {
		err := New().Validate(context.Background(), `package stratium.policy

deny if {
	input.agent.trust_tier != "CERTIFIED"
}`)
		if err != nil {
			t.Fatalf("Validate rejected a correctly-typed inequality comparison: %v", err)
		}
	})

	t.Run("inequality against an unknown operand still validates normally", func(t *testing.T) {
		t.Run("open tenant map key", func(t *testing.T) {
			err := New().Validate(context.Background(), `package stratium.policy

deny if {
	input.resource.classification != "restricted"
}`)
			if err != nil {
				t.Fatalf("Validate rejected != against an open tenant-map key: %v", err)
			}
		})

		t.Run("variable", func(t *testing.T) {
			err := New().Validate(context.Background(), `package stratium.policy

deny if {
	tier := input.derived_tier
	tier != 2
}`)
			if err != nil {
				t.Fatalf("Validate rejected != against a local variable: %v", err)
			}
		})
	})
}

// TestPrepare_SchemaAloneRejectsMismatchedEquality isolates
// inputSchemaSet's own contribution from checkComparisonTypes':
// mismatchedEqualityText uses == (Rego's "equal" builtin), which
// checkComparisonTypes never inspects (see orderingOperators' doc comment)
// — only regolib.Schemas(inputSchemaSet), attached directly to
// regolib.New in Prepare, can reject it. Without this test, removing
// regolib.Schemas(inputSchemaSet) from Prepare entirely would leave every
// other test in this file green, since both of mismatchedComparisonText and
// mismatchedOrdinalText above are caught by checkComparisonTypes
// independently of whether the schema is attached at all.
func TestPrepare_SchemaAloneRejectsMismatchedEquality(t *testing.T) {
	t.Run("string field compared for equality against a number is rejected, naming the policy", func(t *testing.T) {
		const wantID = "mismatched-equality-under-test"
		_, err := New().Prepare(context.Background(), []policy.StoredPolicy{
			{ID: wantID, Name: "schema-only-check", Text: mismatchedEqualityText},
		})
		if err == nil {
			t.Fatal("Prepare accepted input.agent.trust_tier == 2, want an error (trust_tier is a string; == against a number can never be true)")
		}
		if !strings.Contains(err.Error(), wantID) {
			t.Errorf("error does not name the offending policy's ID %q: %v", wantID, err)
		}
	})

	// Positive control: a same-kind equality comparison on the identical
	// field must keep preparing normally.
	t.Run("correctly-typed equality still prepares normally", func(t *testing.T) {
		_, err := New().Prepare(context.Background(), []policy.StoredPolicy{
			{ID: "same-kind-eq-under-test", Name: "correct", Text: `package stratium.policy

allow if {
	input.agent.trust_tier == "CERTIFIED"
}`},
		})
		if err != nil {
			t.Fatalf("Prepare rejected a correctly-typed equality comparison: %v", err)
		}
	})
}

// TestValidate_SchemaAloneRejectsMismatchedEquality is
// TestPrepare_SchemaAloneRejectsMismatchedEquality's counterpart for
// Validate, for the same "each call site can regress on its own" reason as
// TestValidate_RejectsMismatchedTypeComparison above.
func TestValidate_SchemaAloneRejectsMismatchedEquality(t *testing.T) {
	t.Run("string field compared for equality against a number is rejected", func(t *testing.T) {
		err := New().Validate(context.Background(), mismatchedEqualityText)
		if err == nil {
			t.Fatal("Validate accepted input.agent.trust_tier == 2, want an error")
		}
	})

	t.Run("correctly-typed equality still validates normally", func(t *testing.T) {
		err := New().Validate(context.Background(), `package stratium.policy

allow if {
	input.agent.trust_tier == "CERTIFIED"
}`)
		if err != nil {
			t.Fatalf("Validate rejected a correctly-typed equality comparison: %v", err)
		}
	})
}

// allowedToCompile are the only functions in this package permitted to call
// PrepareForEval: Prepare (the compile-once step) and Validate (the PAP's
// authoring-time check, which also compiles text but is never called on a
// per-decision path). See TestPrepareForEval_OnlyCalledFromPrepareOrValidate.
var allowedToCompile = map[string]bool{
	"Prepare":  true,
	"Validate": true,
}

// TestPrepareForEval_OnlyCalledFromPrepareOrValidate guards spec defect D5
// by name: the predecessor called rego.New(...).PrepareForEval inside
// Evaluate, once per policy per decision, instead of once per policy inside
// Prepare. No behavioural test can catch that regression — a version of this
// engine that recompiles on every Evaluate call produces byte-identical
// verdicts to one that reuses a prepared query, just far slower, and none of
// this package's other tests measure time (confirmed directly: the full
// mutation — moving the compile call into Evaluate and having it evaluate
// against the freshly recompiled query — was applied and every behavioural
// test in this package still passed). This is a structural check instead: it
// parses every non-test .go file in this package, walks every top-level
// function and method declaration, and fails if a call to PrepareForEval
// appears inside any function not named in allowedToCompile. "Move
// PrepareForEval into Evaluate" is exactly the source-shape change this
// catches.
func TestPrepareForEval_OnlyCalledFromPrepareOrValidate(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("listing package source: %v", err)
	}

	fset := token.NewFileSet()
	totalCalls := 0
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
			calls := prepareForEvalCallCount(fn.Body)
			if calls == 0 {
				continue
			}
			totalCalls += calls
			if !allowedToCompile[fn.Name.Name] {
				t.Errorf("%s (in %s) calls PrepareForEval %d time(s) — only Prepare and Validate may compile; "+
					"a compile call anywhere else (Evaluate, above all) reintroduces spec defect D5, recompiling "+
					"on every decision instead of reusing what Prepare already built",
					fn.Name.Name, name, calls)
			}
		}
	}

	// Positive control: if the scan found nothing at all, the guard above
	// passes vacuously regardless of what Evaluate does — a wrong glob or a
	// renamed method (PrepareForEval itself, or Prepare/Validate) would
	// silently defeat this test rather than failing it. See
	// policy_test.go's TestNoExportedConstructorAllows for the same
	// "found no candidates" guard applied to a different structural check.
	if totalCalls == 0 {
		t.Fatal("found zero calls to PrepareForEval anywhere in this package — the guard isn't exercising anything, fix the scan")
	}
}

// prepareForEvalCallCount counts calls to a method or function named
// PrepareForEval within node, whether reached through a selector
// (x.PrepareForEval(...)) or a bare identifier (a dot-imported or
// locally-aliased call — not used anywhere in this package today, but the
// guard should not depend on that staying true).
func prepareForEvalCallCount(node ast.Node) int {
	count := 0
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			if fun.Sel.Name == "PrepareForEval" {
				count++
			}
		case *ast.Ident:
			if fun.Name == "PrepareForEval" {
				count++
			}
		}
		return true
	})
	return count
}
