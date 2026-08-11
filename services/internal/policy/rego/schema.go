package rego

import (
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/util"
)

// This file is Task 3's fix for the one finding in the phase-wide engine
// review where a wrong policy widens rather than going inert: Rego totally
// orders values across types (numbers sort before strings), so
//
//	allow if { input.agent.trust_tier > 2 }     trust_tier is a STRING
//	allow if { input.derived_tier <= "2" }      derived_tier is a NUMBER
//
// are not type errors, they are unconditional truths — an operator porting
// Cedar's idiomatic `context.derived_tier > 2` onto the wrong Rego field gets
// an unconditional principal-leg allow instead of a rejection.
//
// # Two mechanisms, not one, because OPA's own schema support only closes
// half the gap
//
// OPA type-checks a compiled module against a JSON Schema for `input` via
// rego.Schemas()/ast.NewSchemaSet() — attached below as inputSchemaSet, wired
// into both Prepare and Validate in engine.go. That alone is NOT sufficient:
// confirmed empirically against this exact OPA release (github.com/open-
// policy-agent/opa v1.19.0) that OPA's `>`, `>=`, `<`, and `<=` builtins
// (ast.GreaterThan et al.) declare both operands as types.A ("any"),
// independently of each other, with no unification between them — that is
// the language deliberately implementing the total order the package doc
// above describes, not a checker gap. A schema-typed `input.agent.trust_tier`
// compared against a numeric literal via `>` compiles cleanly with the
// schema attached and without it, identically. Only `=` and `==` go through a
// different, unification-based check (ast.checkExprEq, keyed off the
// operator name "eq") that DOES catch a schema-typed field compared against
// the wrong literal type — so inputSchemaSet alone already closes that half
// of the gap, verified the same way. checkComparisonTypes below is the
// supplement for the half the schema mechanism cannot reach: a direct walk
// for gt/gte/lt/lte calls whose two operands are both statically known, and
// disagree.
//
// # One description, not two
//
// checkComparisonTypes must not hand-maintain its own copy of what type each
// input field is — that is exactly the drift the task brief warns is silent
// in the dangerous direction (a field either description omits goes
// unchecked). schemaDoc, the parsed form of inputSchemaJSON, is parsed once
// and is the only place any field's type is written down; both
// inputSchemaSet (which feeds rego.Schemas()) and checkComparisonTypes'
// fieldKind lookups read it. schema_test.go's drift test walks a fully
// populated buildInput output and fails if any key it finds is undeclared
// here, so a field added to input.go without a matching schema edit fails
// the build rather than silently going unchecked.
//
// # Why the three tenant-supplied maps stay undeclared
//
// principal.attributes, resource, and delegation.classification_caps are
// free-form tenant maps with no fixed key set to enumerate — the same
// reasoning cedar/deadform.go and xacml/schema.go give for the identical
// fields ("Principal.Attributes and Resource are tenant-supplied free-form
// maps with no fixed field set to enumerate"). A JSON Schema object with no
// declared "properties" type-checks as fully open in OPA's translator
// (confirmed by reading ast/compile.go's parseSchemaWithPropertyKey: an
// object schema with zero declared properties becomes
// types.NewObject(nil, types.NewDynamicProperty(types.A, types.A)), i.e.
// every key maps to type Any) — exactly the "don't over-reject a policy
// reading a tenant-supplied key" requirement this task is warned about.
// Declaring "properties" on these three, even to describe them as open,
// would flip OPA's translator to a CLOSED object (verified the same way:
// any non-empty "properties" list makes the object closed, regardless of
// "additionalProperties"), rejecting every tenant key reference outright.
//
// Every other field below is closed (its parent object declares
// "properties" for exactly its real keys): input.go's buildInput,
// agentDoc, and delegationDoc are exhaustive — no field they emit is
// conditionally absent — so a reference to any other name under principal,
// action, agent, or delegation was already silently dead (never any such
// key) before this task; closing those objects converts that silent
// dead-on-arrival reference into a loud compile error, which only narrows.
const inputSchemaJSON = `{
  "type": "object",
  "properties": {
    "principal": {
      "type": "object",
      "properties": {
        "subject": {"type": "string"},
        "attributes": {"type": "object"}
      },
      "required": ["subject", "attributes"],
      "additionalProperties": false
    },
    "action": {
      "type": "object",
      "properties": {
        "tool": {"type": "string"}
      },
      "required": ["tool"],
      "additionalProperties": false
    },
    "resource": {"type": "object"},
    "derived_tier": {"type": "integer"},
    "agent": {
      "type": "object",
      "properties": {
        "id": {"type": "string"},
        "trust_tier": {"type": "string"},
        "enabled": {"type": "boolean"},
        "suspended": {"type": "boolean"},
        "allowed_tools": {"type": "array", "items": {"type": "string"}}
      },
      "required": ["id", "trust_tier", "enabled", "suspended", "allowed_tools"],
      "additionalProperties": false
    },
    "delegation": {
      "type": "object",
      "properties": {
        "depth": {"type": "integer"},
        "max_action_tier": {"type": "string"},
        "classification_caps": {"type": "object"},
        "purpose": {"type": "string"}
      },
      "required": ["depth", "max_action_tier", "classification_caps", "purpose"],
      "additionalProperties": false
    }
  },
  "required": ["principal", "action", "resource", "derived_tier", "agent", "delegation"],
  "additionalProperties": false
}`

// schemaDoc is inputSchemaJSON parsed once at package init, and is the single
// source both inputSchemaSet and checkComparisonTypes read from — see the
// package-level comment above.
var schemaDoc = mustParseInputSchema(inputSchemaJSON)

// inputSchemaSet is built once and reused, read-only, by every Prepare and
// Validate call: schemaSet.Get is the only method the OPA compiler ever
// calls on it (confirmed by reading ast/compile.go's checkTypes and init —
// neither writes back), so sharing one instance across every policy in a
// Prepare call, and across concurrent Prepare/Validate calls, needs no
// locking. Rebuilding it per policy would mean re-parsing the identical JSON
// up to 100 times in a single Prepare call — pure waste this engine, the
// most expensive of the four to compile with already, cannot afford.
var inputSchemaSet = newInputSchemaSet(schemaDoc)

// mustParseInputSchema decodes raw into the map[string]any shape
// ast.SchemaSet.Put and this file's own fieldKind both need. raw is the
// package-level constant above, not external input, so a decode failure is a
// bug in this file caught the instant any test imports this package — the
// same "fail loudly at init, not at a caller" posture models' own enum
// String() methods use for out-of-range values, applied to a constant
// instead of a runtime value.
func mustParseInputSchema(raw string) map[string]any {
	var doc any
	if err := util.Unmarshal([]byte(raw), &doc); err != nil {
		panic(fmt.Sprintf("rego: inputSchemaJSON is not valid JSON: %v", err))
	}
	m, ok := doc.(map[string]any)
	if !ok {
		panic("rego: inputSchemaJSON must decode to a JSON object")
	}
	return m
}

// newInputSchemaSet wraps doc at ast.SchemaRootRef — the path OPA's compiler
// actually reads as the global input schema (ast/compile.go's checkTypes and
// init both call c.schemaSet.Get(SchemaRootRef) to populate c.inputType,
// which is what ends up typing every `input` reference). Confirmed
// empirically against this exact OPA release, not assumed from the
// rego.Schemas doc comment alone: a schema Put at SchemaRootRef measurably
// rejects a mismatched `==` comparison at PrepareForEval; the same schema
// left unattached does not.
func newInputSchemaSet(doc map[string]any) *ast.SchemaSet {
	ss := ast.NewSchemaSet()
	ss.Put(ast.SchemaRootRef, doc)
	return ss
}

// orderingOperators maps each ordering builtin's canonical name — what
// Expr.Operator().String() returns — to the infix symbol an author actually
// wrote, for error text a policy author recognizes. Rego compiles >, >=, <,
// and <= to gt, gte, lt, and lte respectively; Expr.String() itself renders
// a parsed comparison back as "gt(input.agent.trust_tier, 2)", not infix
// (confirmed empirically), which is why this map exists rather than reusing
// it.
//
// Deliberately excludes eq/equal (=, ==): those already go through OPA's own
// unification-based type check (see the package comment above) and adding
// them here would just duplicate a check that already exists. Also excludes
// neq (!=): a schema-typed field compared for inequality against the wrong
// literal type has the identical latent gap (confirmed empirically the same
// way) and is the same shape of bug, but it is not one of the two forms this
// task's brief names, and unlike >/>=/</<=, != is common in legitimately
// well-typed policies, so adding it needs its own review of what a false
// positive would look like rather than piggybacking on this task — recorded
// here so it is not lost, the same way the task brief itself records the
// batched-compile question as out of scope rather than silently dropping it.
var orderingOperators = map[string]string{
	"gt":  ">",
	"gte": ">=",
	"lt":  "<",
	"lte": "<=",
}

// checkComparisonTypes parses text and rejects the first gt/gte/lt/lte call
// whose two operands are both statically known — one side from a literal,
// one side from schemaDoc — to be different JSON kinds. It runs after
// checkPackage succeeds (see engine.go's Prepare and Validate): a module
// that fails to parse, or declares the wrong package, has nothing here worth
// checking.
//
// Either operand resolving to "unknown" (a variable, a computed index, a key
// under one of the three open tenant maps, a function call's result) is
// never an error — this check only narrows on pairs it can actually prove
// disagree, per the task's own binding constraint that a schema stricter
// than the real input document would reject working policies.
func checkComparisonTypes(id, text string) error {
	mod, err := ast.ParseModule(id, text)
	if err != nil {
		return err
	}

	var problems []error
	ast.WalkExprs(mod, func(expr *ast.Expr) bool {
		if err := checkComparisonExpr(expr); err != nil {
			problems = append(problems, err)
		}
		return false
	})
	if len(problems) > 0 {
		return problems[0]
	}
	return nil
}

// checkComparisonExpr is checkComparisonTypes' per-expression check —
// factored out so the walk callback stays a single line of dispatch.
func checkComparisonExpr(expr *ast.Expr) error {
	if !expr.IsCall() {
		return nil
	}
	symbol, isOrdering := orderingOperators[expr.Operator().String()]
	if !isOrdering {
		return nil
	}
	operands := expr.Operands()
	if len(operands) != 2 {
		return nil
	}

	kindA, okA := operandKind(operands[0])
	kindB, okB := operandKind(operands[1])
	if !okA || !okB || kindA == kindB {
		return nil
	}
	return fmt.Errorf(
		"%s %s %s compares a %s with a %s — Rego orders values across types by a fixed rule instead of raising an error here, "+
			"so this condition is not the type-safe comparison it looks like; mismatched-type %s/%s/%s/%s comparisons against input "+
			"fields are rejected at authoring time",
		operands[0], symbol, operands[1], kindA, kindB, ">", ">=", "<", "<=",
	)
}

// operandKind resolves term's normalized kind ("string", "number", or
// "boolean") from a literal's own AST type, or from schemaDoc for an
// input.* reference. ok is false whenever the kind cannot be determined
// statically — never treated as a kind of its own, so a term this cannot
// classify is silently ignored rather than misreported as a mismatch.
func operandKind(term *ast.Term) (kind string, ok bool) {
	switch v := term.Value.(type) {
	case ast.String:
		return "string", true
	case ast.Number:
		return "number", true
	case ast.Boolean:
		return "boolean", true
	case ast.Ref:
		path, isInput := inputPath(v)
		if !isInput {
			return "", false
		}
		return fieldKind(path)
	default:
		return "", false
	}
}

// inputPath returns ref's dot-path segments — e.g. ["agent", "trust_tier"]
// for input.agent.trust_tier — when ref is rooted at the `input` document
// and every subsequent element is a static string index. ok is false for
// anything else (a bare var, a bracket index computed from a variable, a ref
// not rooted at input): none of those name a fixed schema path, so callers
// must treat a false ok as "unknown," not as a path of its own.
func inputPath(ref ast.Ref) (path []string, ok bool) {
	if len(ref) == 0 {
		return nil, false
	}
	root, isVar := ref[0].Value.(ast.Var)
	if !isVar || root.String() != "input" {
		return nil, false
	}
	for _, term := range ref[1:] {
		s, isString := term.Value.(ast.String)
		if !isString {
			return nil, false
		}
		path = append(path, string(s))
	}
	return path, true
}

// fieldKind resolves the normalized kind schemaDoc declares at path, by
// walking "properties" one segment at a time. ok is false the instant the
// walk reaches a node with no declared "properties" — either because path
// runs into one of the three deliberately open tenant maps (see the
// package-level comment above), or because path names a field schemaDoc
// does not describe at all — so an open or unrecognized field is always
// "unknown," never misreported as a spurious kind.
func fieldKind(path []string) (kind string, ok bool) {
	node := schemaDoc
	for i, segment := range path {
		props, hasProps := node["properties"].(map[string]any)
		if !hasProps {
			return "", false
		}
		next, declared := props[segment]
		if !declared {
			return "", false
		}
		nextNode, _ := next.(map[string]any)
		if i == len(path)-1 {
			t, _ := nextNode["type"].(string)
			return normalizeJSONSchemaKind(t), t != ""
		}
		node = nextNode
	}
	return "", false
}

// normalizeJSONSchemaKind collapses JSON Schema's "integer" and "number"
// into one "number" kind: Rego/JSON draw no such distinction at the value
// level (inputSchemaJSON only ever uses "integer", but a future edit using
// "number" instead must not silently stop matching literals here).
func normalizeJSONSchemaKind(t string) string {
	if t == "integer" || t == "number" {
		return "number"
	}
	return t
}
