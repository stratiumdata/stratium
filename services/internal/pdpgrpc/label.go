// label.go is where a resource's classification comes from (spec §3.9.1
// R4-R7, R10): the tenant's own prefix rules, resolved against the resource
// identity the PDP itself extracted, written onto the attribute map CheckCap
// reads. R3 recorded that nothing supplied a label at all, which made every
// configured cap deny under R2; this file closes that.
//
// It draws the same boundary extract.go does, from the other side. That file
// may look up WHICH field holds the resource id and never what the value
// MEANS; this one says what the value means and never looks at a field the
// caller named. Classification is the PDP's to decide (R1) — a PEP that
// supplied one would be a client asserting a security-relevant fact the
// server cannot check.
package pdpgrpc

import (
	"log/slog"

	"stratium/pkg/classification"
)

// labelResource returns resource with the tenant's own classification label
// written onto it, and logs what winning cost (R6, R10).
//
// The PDP OWNS the two label keys on this path, which is why they are
// stripped unconditionally before anything is written. R1 forecloses a
// caller-supplied classification on principle, and neither PEP in this repo
// sends one — but DecideRequest.resource is a caller-supplied map that
// survives unchanged for an uncataloged tool, so "no PEP does it" is a fact
// about the clients in this repository, not a property of the server.
// Stripping makes it the latter: a claimed `classification: UNCLASSIFIED`
// cannot satisfy a cap here even when no rule matched and there is nothing to
// replace it with. That is also the ONLY direction this can fail safely in —
// leaving the claim would let the cheapest possible bypass through.
//
// resourceID is the id internal/authz.ExtractFromCatalog read out of this
// call's raw_input through the tenant's own catalog row — NOT resource["id"],
// which is where an earlier version of this function looked, and not any
// other map key. The difference is the whole of R4's safety argument.
//
// R4 permits labelling an agent-influenced identifier for one specific
// reason: "the id is what the tool actually acts on. Naming a different
// resource changes what you get, not merely what you are permitted; lying
// does not pay." That holds only where the id was derived server-side from
// the field the tool operates on. ApplyExtraction returns the caller's map
// untouched for a tool with no catalog row, so reading resource["id"] there
// resolved the tenant's rules against a string the caller simply typed —
// nothing tied it to raw_input, and naming a decoy under a permissive rule
// cost one field and bought a label. That is the same escalation stripping
// the classification attribute closed, one indirection further out: the
// claim was gone and the lever that selects it was not.
//
// Taking the id as a parameter makes R4's premise true by construction
// rather than by assumption. An uncataloged tool yields ExtractedInput's zero
// value, so resourceID is "" and nothing is labelled — the resource stays
// unlabelled and R2 denies it under any configured cap. Fail-closed, and it
// costs nothing today: no PEP in this repo populates the resource map at all.
//
// No id, no label, even under R7's empty-prefix catch-all. Resolve would
// match "" against the catch-all quite happily, and doing so would invent a
// fact about a resource nobody identified — which under a PUBLIC catch-all
// ALLOWS. Skipping is strictly fail-closed, for both the uncataloged case
// above and a cataloged call that simply carried no such field.
//
// And no fallback when nothing matched. There is no default level here, not
// even the lowest one: a default would be this file answering a question the
// tenant's rules did not, and "unclassified" is a real level that a cap can
// be satisfied BY. An unmatched resource is unlabelled, and R2/R7 make that
// deny at CheckCap — loudly, with a reason that says the cap could not be
// evaluated rather than that it was met. That denial is the designed
// behaviour, and R7's operator documentation is where it is answered (write a
// catch-all), not here.
//
// Returned fresh rather than mutated: for an uncataloged tool this map IS
// req.Resource, and rewriting a caller's request in place would leave the
// audit trail describing something other than what arrived.
func labelResource(rules []classification.Rule, resource map[string]string, resourceID string) map[string]string {
	labelled := make(map[string]string, len(resource)+2)
	for k, v := range resource {
		if k == classification.AttrClassification || k == classification.AttrHierarchy {
			continue
		}
		labelled[k] = v
	}

	if resourceID == "" {
		return labelled
	}
	match, ok := classification.Resolve(rules, resourceID)
	if !ok {
		return labelled
	}
	labelled[classification.AttrClassification] = match.Rule.Level
	labelled[classification.AttrHierarchy] = match.Rule.Hierarchy
	logCarveOut(match)
	return labelled
}

// logCarveOut emits R6's lowering signal, R10's hierarchy-switch signal, and
// the inert-rule signal beside them. Three lines, never one merged one: a
// switch is not a lowering and an unrankable rule is neither, so folding any
// pair together would put a claim the code cannot support into the only
// signal an operator has. All three can fire for one match, and each is
// independently true when it does.
//
// The three carry the same six fields for the same reason — an operator
// greps one shape, not three — including overrides_hierarchy on every line.
// It looks redundant on the lowering line, where the two hierarchies are the
// same hierarchy, and is not: overriddenBy matches with EqualFold, so the
// overridden ROW can read "NATO" where the winner reads "nato", and a line
// that printed only the winner's spelling would send an operator grepping
// for a string their table does not contain.
//
// WHAT IT CARRIES: the two rules, each as prefix + hierarchy + level. That is
// what an operator needs to find the row and decide whether they meant it,
// and it is what only this code path saw — nothing downstream can re-derive
// the losing candidate, because only Resolve ever looked at it.
//
// WHAT IT DELIBERATELY DOES NOT CARRY: the resource id, and anything else
// about the request. The distinction is not squeamishness about paths, it is
// provenance. A rule's prefix, hierarchy, and level are operator-authored
// configuration for this tenant; a resource id is derived from
// client-supplied raw_input (§4.4.2 T2) and is therefore attacker-influenced
// content in a process log that may be shipped somewhere the decision's
// subject matter should not go. pkg/audit already refuses to store raw tool
// input for the same reason, keeping only a digest, and honoredOverrides
// (server.go) already draws this exact line for its own dropped-override
// line: the row, and nothing about the request that happened to observe it.
// Nor the tenant — this process serves exactly one, named at startup — nor
// the subject or agent, which would turn a configuration warning into a
// per-caller access record.
//
// Level, not Warn. honoredOverrides warns because a dropped override is
// always wrong: either a mistake or a write that bypassed the control plane.
// A lowering carve-out is the FEATURE — R6 rules that a public file inside a
// secret directory is genuinely public — so warning on every one would cry
// wolf on correct configuration and train an operator to filter exactly the
// line that also catches the mistyped rule. The PDP's handler emits Info by
// default (cmd/stratium-pdp/main.go passes nil options), so this is visible
// without configuration.
//
// It fires on every decision under a hot carve-out, and is left that way. The
// line carries nothing request-specific by construction, so every repeat is
// byte-identical and collapses under any log tooling; suppressing repeats in
// process would need state and a clock on the decision path, and would make
// the signal depend on how recently this replica restarted — an operator who
// greps and finds nothing would conclude their carve-out is inert. If volume
// ever does bite, the dedupe key is already sitting in the line: the pair of
// rules, which is the only thing that varies.
func logCarveOut(match classification.Match) {
	if r := match.LoweredFrom; r != nil {
		slog.Info("resource label carve-out lowers the classification it overrides",
			"rule_prefix", match.Rule.Prefix,
			"rule_hierarchy", match.Rule.Hierarchy,
			"rule_level", match.Rule.Level,
			"overrides_prefix", r.Prefix,
			"overrides_hierarchy", r.Hierarchy,
			"overrides_level", r.Level)
	}
	if r := match.SwitchedHierarchyFrom; r != nil {
		slog.Info("resource label carve-out changes hierarchy: a cap naming only the hierarchy it left does not apply to the one it entered",
			"rule_prefix", match.Rule.Prefix,
			"rule_hierarchy", match.Rule.Hierarchy,
			"rule_level", match.Rule.Level,
			"overrides_prefix", r.Prefix,
			"overrides_hierarchy", r.Hierarchy,
			"overrides_level", r.Level)
	}
	if r := match.OverrodeUnrankable; r != nil {
		slog.Info("resource label carve-out covers a rule whose level this system cannot rank: that rule is inert",
			"rule_prefix", match.Rule.Prefix,
			"rule_hierarchy", match.Rule.Hierarchy,
			"rule_level", match.Rule.Level,
			"overrides_prefix", r.Prefix,
			"overrides_hierarchy", r.Hierarchy,
			"overrides_level", r.Level)
	}
}
