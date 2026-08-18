package classification

import "testing"

// natoSecretTree is the fixture most tests below start from: a broad rule and
// a narrower one inside it, deliberately listed LONGEST FIRST so that an
// implementation which returns the first match, or the last, resolves the
// wrong one. Every test that cares about ordering re-lists the same rules in
// the other order rather than trusting this one.
func natoSecretTree() []Rule {
	return []Rule{
		{Prefix: "/data/reports/", Hierarchy: "nato", Level: "TOP-SECRET"},
		{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
	}
}

// R6: the longest matching prefix wins over a shorter one. Kills the
// shortest-match mutant, and — separately — the first-match and last-match
// mutants, because the fixture is listed longest-first and the mirror test
// below lists it shortest-first.
func TestResolve_LongestPrefixWins(t *testing.T) {
	m, ok := Resolve(natoSecretTree(), "/data/reports/q3.pdf")
	if !ok {
		t.Fatal("a resource id covered by a rule must resolve to a label")
	}
	if m.Rule.Prefix != "/data/reports/" {
		t.Errorf("longest prefix must win: got prefix %q, want /data/reports/", m.Rule.Prefix)
	}
	if m.Rule.Level != "TOP-SECRET" {
		t.Errorf("longest prefix must win: got level %q, want TOP-SECRET", m.Rule.Level)
	}
}

// The same rules in the opposite slice order must resolve identically. A
// matcher whose answer depends on the order the store happened to return
// rows in is a matcher whose decisions are not reproducible.
func TestResolve_LongestPrefixWinsRegardlessOfSliceOrder(t *testing.T) {
	reversed := []Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/data/reports/", Hierarchy: "nato", Level: "TOP-SECRET"},
	}
	m, ok := Resolve(reversed, "/data/reports/q3.pdf")
	if !ok {
		t.Fatal("a resource id covered by a rule must resolve to a label")
	}
	if m.Rule.Level != "TOP-SECRET" {
		t.Errorf("slice order must not change the winner: got %q, want TOP-SECRET", m.Rule.Level)
	}
}

// A carve-out that RAISES is still a longest-prefix win, and must not be
// reported as lowering. Kills the mutant that sets the lowering report
// unconditionally — which the lowering test below cannot kill on its own.
func TestResolve_RaisingCarveOutIsNotReportedAsLowering(t *testing.T) {
	m, ok := Resolve(natoSecretTree(), "/data/reports/q3.pdf")
	if !ok {
		t.Fatal("a resource id covered by a rule must resolve to a label")
	}
	if m.LoweredFrom != nil {
		t.Errorf("a carve-out that raises must not be reported as lowering, got %+v", *m.LoweredFrom)
	}
}

// R6's mirror risk: a narrow rule inside a broad one that resolves LOWER.
// The label is honoured — a public file inside a secret directory is
// genuinely public — and the override is reported, because the PDP's log of
// it is the operator's only signal that the carve-out is doing something.
//
// Both halves are asserted separately: an implementation that resolved
// correctly and reported nothing behaves correctly and tells the operator
// nothing, which is exactly how a mistyped carve-out goes unnoticed.
func TestResolve_LoweringCarveOutIsResolvedAndReported(t *testing.T) {
	rules := []Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/data/public/", Hierarchy: "nato", Level: "UNCLASSIFIED"},
	}
	m, ok := Resolve(rules, "/data/public/brochure.pdf")
	if !ok {
		t.Fatal("a resource id covered by a rule must resolve to a label")
	}
	if m.Rule.Level != "UNCLASSIFIED" {
		t.Fatalf("the lowering carve-out must be honoured: got %q, want UNCLASSIFIED", m.Rule.Level)
	}
	if m.LoweredFrom == nil {
		t.Fatal("a carve-out resolving lower than the rule it overrides must be reported")
	}
	// Named, not merely flagged: a bare boolean would tell an operator that
	// SOMETHING lowered without saying what it overrode, and the matcher is
	// the only thing that saw the next-longest match.
	if m.LoweredFrom.Prefix != "/data/" {
		t.Errorf("the report must name the overridden rule: got prefix %q, want /data/", m.LoweredFrom.Prefix)
	}
	if m.LoweredFrom.Level != "SECRET" {
		t.Errorf("the report must name the overridden level: got %q, want SECRET", m.LoweredFrom.Level)
	}
}

// Equal levels are not a lowering. Kills a mutant that reports on `<=`
// instead of `<` — which every other lowering test would still pass.
func TestResolve_SameLevelOverrideIsNotLowering(t *testing.T) {
	rules := []Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/data/inner/", Hierarchy: "nato", Level: "SECRET"},
	}
	m, ok := Resolve(rules, "/data/inner/x")
	if !ok {
		t.Fatal("a resource id covered by a rule must resolve to a label")
	}
	if m.LoweredFrom != nil {
		t.Errorf("an override at the same level is not a lowering, got %+v", *m.LoweredFrom)
	}
}

// Level and hierarchy comparisons fold case exactly as Index does, so a rule
// written "secret" and one written "SECRET" rank identically. A lowering
// report that compared these as strings would call this a lowering.
func TestResolve_LoweringComparisonFoldsCaseLikeIndex(t *testing.T) {
	rules := []Rule{
		{Prefix: "/data/", Hierarchy: "NATO", Level: "SECRET"},
		{Prefix: "/data/inner/", Hierarchy: "nato", Level: "secret"},
	}
	m, ok := Resolve(rules, "/data/inner/x")
	if !ok {
		t.Fatal("a resource id covered by a rule must resolve to a label")
	}
	if m.LoweredFrom != nil {
		t.Errorf("levels differing only in case are the same level, got %+v", *m.LoweredFrom)
	}
}

// "The rule it overrides" can only be a rule in the SAME hierarchy: a level
// is higher or lower only within one ordering, and Index returns -1 across
// hierarchies rather than a comparable number.
//
// This fixture supplies every competing source, not the subset a correct
// implementation consults: the next-longest match OVERALL is the commercial
// rule, and the rule actually overridden is the nato one further out. An
// implementation that took the next-longest match without filtering by
// hierarchy would report nothing here and pass every other lowering test.
func TestResolve_LoweringIsMeasuredWithinTheWinnersHierarchy(t *testing.T) {
	rules := []Rule{
		{Prefix: "/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/data", Hierarchy: "commercial", Level: "PUBLIC"},
		{Prefix: "/data/x", Hierarchy: "nato", Level: "UNCLASSIFIED"},
	}
	m, ok := Resolve(rules, "/data/x/file")
	if !ok {
		t.Fatal("a resource id covered by a rule must resolve to a label")
	}
	if m.Rule.Prefix != "/data/x" {
		t.Fatalf("longest prefix must win: got %q, want /data/x", m.Rule.Prefix)
	}
	if m.LoweredFrom == nil {
		t.Fatal("the nato rule at / is lowered by the nato rule at /data/x and must be reported")
	}
	if m.LoweredFrom.Prefix != "/" {
		t.Errorf("the overridden rule must be the nearest one in the winner's hierarchy: got %q, want /",
			m.LoweredFrom.Prefix)
	}
}

// A cross-hierarchy override is not a lowering and must not be reported as
// one. There is no ordering that ranks a commercial level against a nato
// level, so any claim that one is "lower" would be a false statement in the
// one log line an operator is meant to trust.
func TestResolve_CrossHierarchyOverrideIsNotReportedAsLowering(t *testing.T) {
	rules := []Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "TOP-SECRET"},
		{Prefix: "/data/inner/", Hierarchy: "commercial", Level: "PUBLIC"},
	}
	m, ok := Resolve(rules, "/data/inner/x")
	if !ok {
		t.Fatal("a resource id covered by a rule must resolve to a label")
	}
	if m.Rule.Hierarchy != "commercial" {
		t.Fatalf("longest prefix must win: got hierarchy %q, want commercial", m.Rule.Hierarchy)
	}
	if m.LoweredFrom != nil {
		t.Errorf("levels in different hierarchies are not comparable, got %+v", *m.LoweredFrom)
	}
}

// R7/R2: no rule matched means NO label, never a default one. The caller
// must be able to tell this apart from a resolved label, because CheckCap
// denies on an unlabelled resource and that denial is the whole point.
func TestResolve_NoMatchYieldsNoLabel(t *testing.T) {
	m, ok := Resolve(natoSecretTree(), "/logs/app.log")
	if ok {
		t.Fatalf("an unmatched resource id must not resolve to a label, got %+v", m.Rule)
	}
	if m.Rule.Level != "" {
		t.Errorf("an unresolved match must carry no level, got %q", m.Rule.Level)
	}
}

func TestResolve_NoRulesYieldsNoLabel(t *testing.T) {
	if _, ok := Resolve(nil, "/data/reports/q3.pdf"); ok {
		t.Error("a tenant with no rules must resolve nothing, not a default")
	}
}

// R7: the empty prefix is how an operator registers a catch-all, and it is
// not a special case — strings.HasPrefix(anything, "") is true, so it falls
// out of prefix semantics. Tested explicitly anyway, because an
// implementation that special-cased it to match nothing would be wrong in a
// way nothing else here catches.
func TestResolve_EmptyPrefixMatchesEverything(t *testing.T) {
	rules := []Rule{{Prefix: "", Hierarchy: "nato", Level: "RESTRICTED"}}
	for _, id := range []string{"/data/reports/q3.pdf", "no-leading-slash", "s3://bucket/key", "/"} {
		m, ok := Resolve(rules, id)
		if !ok {
			t.Fatalf("the empty prefix must match %q", id)
		}
		if m.Rule.Level != "RESTRICTED" {
			t.Errorf("the catch-all must label %q RESTRICTED, got %q", id, m.Rule.Level)
		}
	}
}

// The empty resource id is the case a special-cased empty prefix is most
// likely to get wrong in the opposite direction: "" is a prefix of "", so
// the catch-all covers it too. A resource id can be empty — resourceFromID
// (internal/authz) omits the key entirely rather than sending "", but this
// function must not depend on that being true forever.
func TestResolve_EmptyPrefixMatchesTheEmptyResourceID(t *testing.T) {
	rules := []Rule{{Prefix: "", Hierarchy: "nato", Level: "RESTRICTED"}}
	m, ok := Resolve(rules, "")
	if !ok {
		t.Fatal("the empty prefix must match the empty resource id")
	}
	if m.Rule.Level != "RESTRICTED" {
		t.Errorf("got %q, want RESTRICTED", m.Rule.Level)
	}
}

// A non-empty prefix must NOT match the empty resource id — the mirror of
// the test above, and what stops "the empty id matches everything" from
// being read as the rule.
func TestResolve_NonEmptyPrefixDoesNotMatchTheEmptyResourceID(t *testing.T) {
	if _, ok := Resolve(natoSecretTree(), ""); ok {
		t.Error("an empty resource id must not match a non-empty prefix")
	}
}

// A catch-all is a rule like any other: the longest match still wins over
// it, and a narrower rule that resolves lower is still reported.
func TestResolve_CatchAllIsOverriddenByALongerPrefix(t *testing.T) {
	rules := []Rule{
		{Prefix: "", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/public/", Hierarchy: "nato", Level: "UNCLASSIFIED"},
	}
	m, ok := Resolve(rules, "/public/x")
	if !ok {
		t.Fatal("a resource id covered by a rule must resolve to a label")
	}
	if m.Rule.Level != "UNCLASSIFIED" {
		t.Errorf("a longer prefix must beat the catch-all: got %q, want UNCLASSIFIED", m.Rule.Level)
	}
	if m.LoweredFrom == nil {
		t.Fatal("lowering the catch-all is still a lowering and must be reported")
	}
	if m.LoweredFrom.Prefix != "" {
		t.Errorf("the overridden rule is the catch-all: got prefix %q, want the empty prefix",
			m.LoweredFrom.Prefix)
	}
}

// THE RULING, and the case a real deployment will get wrong: matching is
// plain string prefix, so /data DOES match /database/x. See Resolve's doc
// comment for why — in short, the alternative needs a separator vocabulary
// the resource id does not carry, and would force R7's empty-prefix
// catch-all to become the special case the brief rules out.
//
// An operator who means the directory writes the separator: /data/.
func TestResolve_PrefixIsPlainStringPrefixNotAPathBoundary(t *testing.T) {
	rules := []Rule{{Prefix: "/data", Hierarchy: "nato", Level: "SECRET"}}

	m, ok := Resolve(rules, "/database/x")
	if !ok {
		t.Fatal("/data is a plain string prefix of /database/x and must match")
	}
	if m.Rule.Level != "SECRET" {
		t.Errorf("got %q, want SECRET", m.Rule.Level)
	}

	// The other half of the ruling: writing the separator is what an
	// operator does to mean the directory, and it must then NOT match the
	// sibling. Without this half the ruling would be untestable advice.
	bounded := []Rule{{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"}}
	if _, ok := Resolve(bounded, "/database/x"); ok {
		t.Error("/data/ must not match /database/x")
	}
	if _, ok := Resolve(bounded, "/data/x"); !ok {
		t.Error("/data/ must still match /data/x")
	}
}

// A boundary-less rule that LOWERS a sibling subtree is the hazard the
// ruling above accepts, and R6's report is what makes it visible. Asserted
// rather than argued: if the report did not fire here, the ruling would be
// trading a silent lowering for nothing.
func TestResolve_BoundarylessLoweringOfASiblingSubtreeIsStillReported(t *testing.T) {
	rules := []Rule{
		{Prefix: "/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/data", Hierarchy: "nato", Level: "UNCLASSIFIED"},
	}
	m, ok := Resolve(rules, "/database/x")
	if !ok {
		t.Fatal("/data matches /database/x under plain prefix semantics")
	}
	if m.LoweredFrom == nil {
		t.Fatal("a mistyped rule that lowers a sibling subtree must be reported")
	}
	if m.LoweredFrom.Prefix != "/" {
		t.Errorf("got overridden prefix %q, want /", m.LoweredFrom.Prefix)
	}
}

// Prefix matching itself is case-SENSITIVE, unlike the level and hierarchy
// comparisons. A resource id is a path the tool will act on, and /Data and
// /data are different resources on a case-sensitive store; folding them
// would silently widen every rule an operator wrote.
func TestResolve_PrefixMatchingIsCaseSensitive(t *testing.T) {
	rules := []Rule{{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"}}
	if _, ok := Resolve(rules, "/DATA/x"); ok {
		t.Error("prefix matching must be case-sensitive: /data/ must not match /DATA/x")
	}
}

// Two rules with the same prefix that disagree are ambiguous, and ambiguity
// resolves to NO label rather than to an arbitrary winner — the same ruling
// lookupCap already applies to two caps differing only by case.
//
// Task 2's key is now (tenant_id, prefix), narrowed after this very pair was
// raised as a legal-but-unsatisfiable row set, so these two rows are
// schema-impossible. The test stays because Resolve does not lean on the
// schema: a stale read or an in-flight migration delivers rows a constraint
// has not yet excluded. This fixture varies hierarchy AND level together —
// the two tests below vary one at a time, which is what pins each half of
// agree independently.
func TestResolve_SamePrefixInTwoHierarchiesResolvesToNoLabel(t *testing.T) {
	rules := []Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/data/", Hierarchy: "commercial", Level: "PUBLIC"},
	}
	if m, ok := Resolve(rules, "/data/x"); ok {
		t.Errorf("an ambiguous longest match must not resolve, got %+v", m.Rule)
	}
}

// The same ambiguity in the other slice order. Two runs are the whole point:
// a matcher that picked the first, or the last, would pass one of these and
// fail the other, and neither on its own proves determinism.
func TestResolve_AmbiguityIsRefusedInEitherSliceOrder(t *testing.T) {
	forward := []Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/data/", Hierarchy: "commercial", Level: "PUBLIC"},
	}
	reverse := []Rule{forward[1], forward[0]}
	if _, ok := Resolve(forward, "/data/x"); ok {
		t.Error("ambiguity must not resolve, whichever rule comes first")
	}
	if _, ok := Resolve(reverse, "/data/x"); ok {
		t.Error("ambiguity must not resolve, whichever rule comes first")
	}
}

// Duplicate rules that AGREE are not ambiguous — there is nothing to pick
// between. Without this the refusal above could be implemented as "more than
// one rule at the winning length denies", which would break a store that
// ever returned a row twice.
func TestResolve_IdenticalDuplicateRulesStillResolve(t *testing.T) {
	rule := Rule{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"}
	m, ok := Resolve([]Rule{rule, rule}, "/data/x")
	if !ok {
		t.Fatal("duplicate rules that agree must still resolve")
	}
	if m.Rule.Level != "SECRET" {
		t.Errorf("got %q, want SECRET", m.Rule.Level)
	}
}

// Rules that agree once case is folded also agree. Postgres unique keys on
// text are case-sensitive, so ("nato", "SECRET") and ("NATO", "secret") are
// two legal rows saying the identical thing.
func TestResolve_DuplicatesAgreeingOnlyAfterFoldingStillResolve(t *testing.T) {
	rules := []Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/data/", Hierarchy: "NATO", Level: "secret"},
	}
	if _, ok := Resolve(rules, "/data/x"); !ok {
		t.Error("rules differing only in case say the same thing and must resolve")
	}
}

// A longer, unambiguous rule settles an ambiguity that exists further out:
// the refusal is about the WINNING length only, not about the rule set as a
// whole.
func TestResolve_AmbiguityFurtherOutDoesNotBlockALongerWinner(t *testing.T) {
	rules := []Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/data/", Hierarchy: "commercial", Level: "PUBLIC"},
		{Prefix: "/data/x/", Hierarchy: "nato", Level: "CONFIDENTIAL"},
	}
	m, ok := Resolve(rules, "/data/x/y")
	if !ok {
		t.Fatal("an unambiguous longest match must resolve even when a shorter length is ambiguous")
	}
	if m.Rule.Level != "CONFIDENTIAL" {
		t.Errorf("got %q, want CONFIDENTIAL", m.Rule.Level)
	}
}

// The matcher does not validate a level against its hierarchy: that is a
// write-time check (Task 2), and a second copy of the rule here would be a
// second thing to drift. The level is passed through verbatim, and CheckCap
// denies on it — Index returns -1 and "unknown classification level" is a
// far more actionable reason than a rule silently not matching.
func TestResolve_UnknownLevelIsPassedThroughNotFilteredOut(t *testing.T) {
	rules := []Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/data/x/", Hierarchy: "nato", Level: "ULTRA-SECRET"},
	}
	m, ok := Resolve(rules, "/data/x/y")
	if !ok {
		t.Fatal("a rule with an unrecognised level still matches; CheckCap is what denies")
	}
	if m.Rule.Level != "ULTRA-SECRET" {
		t.Errorf("the level must be passed through verbatim, got %q", m.Rule.Level)
	}
	// And it must not be reported as a lowering: an unrankable level cannot
	// be shown to be lower than anything. Index returns -1 for it, and -1
	// compares as lower than every real rank — so an implementation that
	// compared the raw Index values would claim a lowering that nobody can
	// substantiate.
	if m.LoweredFrom != nil {
		t.Errorf("an unrankable level cannot be reported as lower than anything, got %+v", *m.LoweredFrom)
	}
}

// An unrankable rule further out is skipped when looking for what the winner
// overrode, rather than blinding the report: the next rankable rule in the
// hierarchy is still the thing being lowered.
func TestResolve_UnrankableOverriddenRuleIsSkippedNotFatal(t *testing.T) {
	rules := []Rule{
		{Prefix: "/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/data", Hierarchy: "nato", Level: "ULTRA-SECRET"},
		{Prefix: "/data/x", Hierarchy: "nato", Level: "UNCLASSIFIED"},
	}
	m, ok := Resolve(rules, "/data/x/y")
	if !ok {
		t.Fatal("a resource id covered by a rule must resolve to a label")
	}
	if m.LoweredFrom == nil {
		t.Fatal("the nearest RANKABLE overridden rule must still be reported")
	}
	if m.LoweredFrom.Prefix != "/" {
		t.Errorf("got overridden prefix %q, want /", m.LoweredFrom.Prefix)
	}
}

// The report must not alias the caller's slice. A caller that reuses or
// mutates the rules it loaded must not be able to change what a completed
// match says it decided.
func TestResolve_ReportDoesNotAliasTheCallersRules(t *testing.T) {
	rules := []Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/data/public/", Hierarchy: "nato", Level: "UNCLASSIFIED"},
	}
	m, ok := Resolve(rules, "/data/public/x")
	if !ok || m.LoweredFrom == nil {
		t.Fatal("fixture must produce a reported lowering")
	}
	rules[0].Level = "TOP-SECRET"
	if m.LoweredFrom.Level != "SECRET" {
		t.Errorf("the report aliased the caller's slice: got %q, want SECRET", m.LoweredFrom.Level)
	}
}

// The label Resolve produces is exactly what CheckCap consumes. Asserted
// end-to-end because the two halves are only useful together: this is the
// gap R3 recorded — CheckCap reads a classification nothing ever supplied.
func TestResolve_FeedsCheckCap(t *testing.T) {
	rules := []Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/data/public/", Hierarchy: "nato", Level: "UNCLASSIFIED"},
	}
	caps := map[string]string{"nato": "CONFIDENTIAL"}

	m, ok := Resolve(rules, "/data/q3.pdf")
	if !ok {
		t.Fatal("fixture must resolve")
	}
	attrs := map[string]string{"classification": m.Rule.Level, "hierarchy": m.Rule.Hierarchy}
	if allowed, reason := CheckCap(caps, attrs); allowed {
		t.Error("SECRET exceeds a CONFIDENTIAL cap and must deny")
	} else if reason == "" {
		t.Error("a denial must carry a reason")
	}

	m, ok = Resolve(rules, "/data/public/brochure.pdf")
	if !ok {
		t.Fatal("fixture must resolve")
	}
	attrs = map[string]string{"classification": m.Rule.Level, "hierarchy": m.Rule.Hierarchy}
	if allowed, reason := CheckCap(caps, attrs); !allowed {
		t.Errorf("the lowering carve-out is under the cap and must allow, got: %s", reason)
	}

	// R7's cliff: an unmatched resource resolves to nothing, and a
	// configured cap then denies. No default level, no fallback.
	if _, ok := Resolve(rules, "/logs/app.log"); ok {
		t.Fatal("fixture must not match")
	}
	if allowed, _ := CheckCap(caps, map[string]string{}); allowed {
		t.Error("an unlabelled resource under a configured cap must deny (R2/R7)")
	}
}

// The rule set below is one Task 2's uniqueness key will forbid — one
// tenant, one prefix, one hierarchy, two levels — and Task 1 ships before
// that key exists. Resolve's doc comment claims it does not lean on the
// constraint; this pins the half of that claim the tests above do not reach.
//
// The winner is unambiguous, so the DECISION is settled either way and only
// the lowering report is at stake. Reporting the larger drop is the choice,
// because a report is a warning and the worse of two readings is the one
// worth showing. What matters more than which is that it is the same on
// every run: found by mutation, where reversing the tie-break survived the
// whole suite.
func TestResolve_OverriddenTieIsBrokenDeterministically(t *testing.T) {
	lower := Rule{Prefix: "/data", Hierarchy: "nato", Level: "CONFIDENTIAL"}
	higher := Rule{Prefix: "/data", Hierarchy: "nato", Level: "TOP-SECRET"}
	winner := Rule{Prefix: "/data/x", Hierarchy: "nato", Level: "UNCLASSIFIED"}

	for _, rules := range [][]Rule{{lower, higher, winner}, {higher, lower, winner}} {
		m, ok := Resolve(rules, "/data/x/file")
		if !ok {
			t.Fatal("the winning prefix is unambiguous and must resolve")
		}
		if m.LoweredFrom == nil {
			t.Fatal("a lowering carve-out must be reported")
		}
		if m.LoweredFrom.Level != "TOP-SECRET" {
			t.Errorf("the reported drop must be the larger one, on every ordering: got %q, want TOP-SECRET",
				m.LoweredFrom.Level)
		}
	}
}

// The canonical ambiguity, and the one classification.go's package comment
// describes in prose: one prefix carrying two answers. It is the only
// fixture here that varies LEVEL alone, which is what pins agree's level
// comparison independently of its hierarchy comparison — every other
// ambiguity fixture varies both at once, so agree reduced to just the
// hierarchy check passes all of them.
//
// Same-hierarchy duplicates stay reachable after Task 2's (tenant_id,
// prefix) key in a way the two-hierarchy pair no longer is: a stale read, an
// in-flight migration, a store bug.
func TestResolve_SamePrefixAndHierarchyWithTwoLevelsResolvesToNoLabel(t *testing.T) {
	rules := []Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/data/", Hierarchy: "nato", Level: "UNCLASSIFIED"},
	}
	if m, ok := Resolve(rules, "/data/x"); ok {
		t.Errorf("one prefix carrying two levels must not resolve, got %+v", m.Rule)
	}
}

// The mirror: varies HIERARCHY alone, pinning agree's other half. The level
// text is identical on both rows, so a comparison that had dropped the
// hierarchy clause would call these two rules the same thing and resolve
// whichever came first.
//
// CONFIDENTIAL is a nato level and not a commercial one, which is beside the
// point twice over: agree is textual and refuses before anything is ranked,
// and a level filed under the wrong hierarchy is exactly the operator typo
// that puts this pair in a table in the first place.
func TestResolve_SamePrefixAndLevelInTwoHierarchiesResolvesToNoLabel(t *testing.T) {
	rules := []Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "CONFIDENTIAL"},
		{Prefix: "/data/", Hierarchy: "commercial", Level: "CONFIDENTIAL"},
	}
	if m, ok := Resolve(rules, "/data/x"); ok {
		t.Errorf("one prefix carrying two hierarchies must not resolve, got %+v", m.Rule)
	}
}

// R7's catch-all is an ordinary rule to the ambiguity check too. Exempting
// the empty prefix there — `len(r.Prefix) > 0 &&` — is the special-casing
// the brief rules out, one branch deeper than the matching test looks, and
// it survived every other test in this file.
func TestResolve_TwoDisagreeingCatchAllsResolveToNoLabel(t *testing.T) {
	rules := []Rule{
		{Prefix: "", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "", Hierarchy: "nato", Level: "UNCLASSIFIED"},
	}
	if m, ok := Resolve(rules, "/anything"); ok {
		t.Errorf("two catch-alls that disagree must not resolve, got %+v", m.Rule)
	}
}

// overriddenBy must ask whether a rule MATCHES the resource, not only
// whether it is shorter than the winner. Every other fixture here happens to
// have all its shorter rules match the id under test, so dropping that guard
// survives the whole suite.
//
// The failure it produces is the worst kind for R6: not silence, but a
// confident log line naming an unrelated rule as the one that got lowered —
// in the single line the operator is asked to trust.
func TestResolve_ANonMatchingRuleIsNeverReportedAsOverridden(t *testing.T) {
	rules := []Rule{
		{Prefix: "/logs/", Hierarchy: "nato", Level: "TOP-SECRET"},
		{Prefix: "/data/x/", Hierarchy: "nato", Level: "UNCLASSIFIED"},
	}
	m, ok := Resolve(rules, "/data/x/f")
	if !ok {
		t.Fatal("the winner must resolve")
	}
	if m.LoweredFrom != nil {
		t.Errorf("a rule the resource does not match cannot have been overridden by it, got %+v",
			*m.LoweredFrom)
	}
}
