package cedar

import "encoding/json"

// This file's structs and helpers decode Cedar's own JSON policy format
// (https://docs.cedarpolicy.com/policies/json-format.html) — the stable,
// cross-SDK wire format every Cedar implementation reads and writes, not a
// cedar-go-specific or experimental shape. deadform.go's checks walk this
// representation, reached via (*cedarlib.Policy).MarshalJSON — a method on
// the stable top-level cedar package — rather than cedar-go's x/exp/ast
// (the richer, directly-walkable AST the schema validator itself uses): see
// deadform.go's package doc for why x/exp was ruled out for the validator
// and that same "no semver guarantee, may break at any time" reasoning
// applies equally to building permanent authoring-time checks on x/exp/ast.
// The JSON format, by contrast, is Cedar-the-language's own spec'd
// interchange format; cedar-go's obligation to keep producing it is the
// same obligation every other Cedar SDK has, independent of this one Go
// module's own internal churn.
//
// Every struct here is intentionally partial: only the fields these checks
// actually read. Unknown JSON fields (annotations, the "entities"/"in"
// scope variants this package doesn't inspect, extension-function calls,
// etc.) decode into nothing and are silently ignored by encoding/json,
// which is the correct default here — this checker's job is to recognize
// specific dead shapes, not to fully model Cedar's grammar, and an
// unrecognized shape must fail OPEN (not matched, not rejected) rather than
// error: see deadform.go's "the safe default direction" note.

// policyJSON is the document (*cedarlib.Policy).MarshalJSON produces.
type policyJSON struct {
	Principal  scopeJSON       `json:"principal"`
	Resource   scopeJSON       `json:"resource"`
	Conditions []conditionJSON `json:"conditions"`
}

// scopeJSON is one of the three parenthesized scope clauses (principal,
// action, or resource). Only the "==" and "is" shapes are represented —
// checkScopeEntityType's own doc comment explains why "in" and "is ... in"
// are deliberately left unhandled.
type scopeJSON struct {
	Op         string         `json:"op"`
	Entity     *entityUIDJSON `json:"entity,omitempty"`
	EntityType string         `json:"entity_type,omitempty"`
}

type entityUIDJSON struct {
	Type string `json:"type"`
}

// conditionJSON is one `when { ... }` or `unless { ... }` clause. Kind is
// read by checkDeadForms to skip "unless" bodies entirely — see its own
// doc comment for why inspecting them would need inverted, and easy to get
// backwards, logic.
type conditionJSON struct {
	Kind string          `json:"kind"`
	Body json.RawMessage `json:"body"`
}

// binaryJSON is the {"left": ..., "right": ...} shape shared by every
// binary Cedar operator (==, !=, <, <=, >, >=, in, contains, &&, ||, ...) —
// which specific operator applies is which JSON key wraps this shape (see
// asOperator), not a field of this struct itself.
type binaryJSON struct {
	Left  json.RawMessage `json:"left"`
	Right json.RawMessage `json:"right"`
}

// asOperator decodes expr as a binary node under whichever of ops is
// present as expr's single top-level key, returning that key. Cedar's JSON
// format keys each binary expression by its own operator name, so "is this
// == or !=" is "which key is present," not a separate discriminator field.
// ok is false if expr is not an object, or is an object but none of ops is
// among its keys (including the common case of expr being some other kind
// of node entirely — {"Value":...}, {"Var":...}, {".":...}, unary {"!":...}
// — every one of which this function correctly declines to match).
func asOperator(expr json.RawMessage, ops ...string) (op string, operands binaryJSON, ok bool) {
	var node map[string]json.RawMessage
	if err := json.Unmarshal(expr, &node); err != nil {
		return "", binaryJSON{}, false
	}
	for _, candidate := range ops {
		inner, present := node[candidate]
		if !present {
			continue
		}
		var b binaryJSON
		if err := json.Unmarshal(inner, &b); err != nil {
			return "", binaryJSON{}, false
		}
		return candidate, b, true
	}
	return "", binaryJSON{}, false
}

// dotPath resolves a chain of Cedar "." (static attribute access) nodes
// back to its root variable, returning the dotted path
// ("context.agent.trust_tier") the checks in deadform.go match against
// their known-path tables. It deliberately does not follow bracket-index
// access ({"index":...}, Cedar's `expr["key"]` form) — those key the
// genuinely tenant-open parts of the request (classification_caps's own
// entries, and every resource/principal attribute — see
// request.go's buildRequest), which this checker must never treat as a
// closed vocabulary; see deadform.go's package doc.
func dotPath(raw json.RawMessage) (string, bool) {
	var asVar struct {
		Var *string `json:"Var"`
	}
	if err := json.Unmarshal(raw, &asVar); err == nil && asVar.Var != nil {
		return *asVar.Var, true
	}

	var node struct {
		Dot *struct {
			Left json.RawMessage `json:"left"`
			Attr string          `json:"attr"`
		} `json:"."`
	}
	if err := json.Unmarshal(raw, &node); err != nil || node.Dot == nil {
		return "", false
	}
	base, ok := dotPath(node.Dot.Left)
	if !ok {
		return "", false
	}
	return base + "." + node.Dot.Attr, true
}

// literalValue reports whether raw is a Cedar literal ({"Value": ...}) and,
// if so, decodes it as a Go string, float64, or bool per encoding/json's
// usual dynamic decoding into any.
func literalValue(raw json.RawMessage) (any, bool) {
	var node struct {
		Value *json.RawMessage `json:"Value"`
	}
	if err := json.Unmarshal(raw, &node); err != nil || node.Value == nil {
		return nil, false
	}
	var v any
	if err := json.Unmarshal(*node.Value, &v); err != nil {
		return nil, false
	}
	return v, true
}

// isEmptySet reports whether raw is a Cedar set literal ({"Set": [...]})
// with zero elements.
func isEmptySet(raw json.RawMessage) bool {
	var node struct {
		Set *[]json.RawMessage `json:"Set"`
	}
	if err := json.Unmarshal(raw, &node); err != nil || node.Set == nil {
		return false
	}
	return len(*node.Set) == 0
}

// pathAndLiteral inspects a binary comparison's two operands and, if
// exactly one side is a dot-path and the other a literal, returns the path
// and the literal's decoded value — regardless of which physical side
// (left or right) each landed on. Cedar's == and != do not care about
// operand order, and a check that only ever looked at one fixed side would
// be silently defeated by an author who happened to write the comparison
// backwards (`"CERTIFIED" == context.agent.trust_tier`).
func pathAndLiteral(left, right json.RawMessage) (path string, lit any, ok bool) {
	if p, pok := dotPath(left); pok {
		if v, vok := literalValue(right); vok {
			return p, v, true
		}
	}
	if p, pok := dotPath(right); pok {
		if v, vok := literalValue(left); vok {
			return p, v, true
		}
	}
	return "", nil, false
}

// conjuncts flattens expr into the list of leaves reached by recursively
// unwrapping only "&&" nodes — see deadform.go's package doc for why this
// stops at "||" and "!" instead of walking every subexpression.
func conjuncts(expr json.RawMessage) []json.RawMessage {
	if _, b, ok := asOperator(expr, "&&"); ok {
		return append(conjuncts(b.Left), conjuncts(b.Right)...)
	}
	return []json.RawMessage{expr}
}
