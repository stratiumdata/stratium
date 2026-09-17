// grantwidens.go answers the OTHER containment question.
//
// Contains (contains.go) asks the DELEGATION question: may a child hold
// this? GrantWidens asks the GRANT question: did this get wider? Those are
// not the same question, and they disagree on exactly one case -- a key the
// after-value introduces and the before-value lacks.
//
// Both questions are legitimate and both are needed. Keeping them as two
// named functions, rather than one function with a flag, is what stops a
// caller reaching for containment and silently getting the wrong one: you
// have to type which question you are asking.
package permset

// GrantWidens reports whether after grants more authority than before,
// returning the reason it does or the empty string when it narrows or is
// unchanged. Argument order reads backwards on purpose, and the reason is
// worth holding onto: Contains(outer, inner) asks whether inner fits inside
// outer, so the BEFORE value is the outer one -- a write widens exactly when
// the after-value does not fit inside what was there already.
//
// # Why this is not a bare Contains call
//
// DO NOT "SIMPLIFY" THIS TO return Contains(before, after). The pre-fill
// below is the whole difference, and removing it puts a FALSE "widened"
// verdict on the most common grant write there is.
//
// WHAT CONTAINS DOES. Given a key the inner set holds and the outer set does
// not, Contains refuses it -- "child caps hierarchy X which parent does not
// cap", "child constrains resource key X which parent does not constrain".
// That is DELIBERATE where Contains was written, and contains.go's own doc
// comment says so and tells you not to "fix" it: those rules are explicitly
// NOT lattice containment (spec §4.3.1). They exist so a child delegation's
// SHAPE is derivable from its parent's -- a child may not invent a dimension
// the parent never had.
//
// WHY THAT ANSWER IS INVERTED HERE. A grant's before/after is a pure LATTICE
// question, not a delegation-shape one. An absent cap means UNRESTRICTED
// (classification.CheckCap allows when len(caps) == 0) and an absent
// constraint key means unrestricted too (internal/authz.checkResourceConstraints
// iterates only the keys present), so introducing either one NARROWS the
// grant. Under a bare Contains, the first cap and the first id_prefix an
// agent ever gets -- the narrowest, most protective writes an operator makes
// -- would each be recorded as a widening, which is the precise failure that
// teaches operators to ignore the verdict.
//
// WHAT THE PRE-FILL DOES, AND ONLY THAT. It copies into the before-value any
// key the after-value introduces, so those two clauses cannot fire. Every
// other clause is untouched, verified against each branch of Contains: a
// DROPPED key still fires (the pre-fill only ever adds to the outer side,
// never the inner), and for a key present in both, the real before-value
// wins (base is copied over extra), so a RAISED cap level and a WIDENED or
// sideways prefix are compared against what was actually there.
//
// WHY NOT REIMPLEMENT AS PURE LATTICE CONTAINMENT. That would mean
// duplicating Contains's comparison minus two clauses, including its frozen
// operator-facing reason strings -- two places for the same strings to
// drift, and verbatim duplication of a logic block. Delegating to Contains
// keeps one implementation of the comparison and one set of reasons.
func GrantWidens(before, after Set) string {
	widened := before
	widened.ClassificationCaps = withIntroducedKeys(before.ClassificationCaps, after.ClassificationCaps)
	widened.ResourceConstraints = withIntroducedKeys(before.ResourceConstraints, after.ResourceConstraints)
	return Contains(widened, after)
}

// withIntroducedKeys returns base plus any key present only in extra, taking
// base's value wherever both have one.
//
// It allocates rather than writing into base: FromDelegation shares its maps
// with the source models.Delegation, so writing through one here would
// corrupt a live delegation record -- and every test that checked only the
// returned verdict would still pass.
func withIntroducedKeys(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range extra {
		out[k] = v
	}
	for k, v := range base {
		out[k] = v
	}
	return out
}
