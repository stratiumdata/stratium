package pdpgrpc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"stratium/pkg/classification"
	"stratium/pkg/models"
)

// labelFixture is the shape every test below starts from: a tenant that has
// cataloged Bash with a "path" resource field, a delegation carrying a nato
// cap, and a call naming a resource under /data/. The catalog row is what
// makes the resource id the PDP's OWN reading of raw_input rather than a
// caller's claim (§4.4.2 T2), which is the only identity R4 is willing to
// label.
func labelFixture(t *testing.T, caps map[string]string, rules []classification.Rule) (*fakeStore, *DecideRequest) {
	t.Helper()
	fs, req := wellFormedFixture()
	resourceField := "path"
	fs.catalog = []models.ToolCatalogEntry{{
		ToolName: "Bash", ActionTier: tierPtr(models.ActionTierReadOnly), ResourceField: &resourceField,
	}}
	fs.chain[0].ClassificationCaps = caps
	fs.labelRules = rules
	req.RawInput = `{"path":"/data/reports/q3.pdf"}`
	return fs, req
}

// The headline property: a tenant's own rule labels the resource, and the
// delegation's cap is enforced against that label. Before this, R3's gap made
// every configured cap deny for want of anything to check.
func TestDecide_LabelledResourceIsDeniedByTheCapItExceeds(t *testing.T) {
	fs, req := labelFixture(t, map[string]string{"nato": "CONFIDENTIAL"}, []classification.Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
	})
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetDelegationEffect() != Effect_EFFECT_DENY {
		t.Fatalf("DelegationEffect = %v (%q), want DENY: SECRET exceeds a CONFIDENTIAL cap",
			resp.GetDelegationEffect(), resp.GetDelegationReason())
	}
	if !strings.Contains(resp.GetDelegationReason(), "SECRET") {
		t.Errorf("DelegationReason = %q, want it to name the level that exceeded the cap",
			resp.GetDelegationReason())
	}
}

// The mirror, and it is not decoration: a rule set that labelled everything
// unrankably, or a wiring that never reached CheckCap at all, would pass the
// denial test above by denying for the wrong reason. This is what says the
// label was read and compared.
func TestDecide_LabelledResourceUnderTheCapIsAllowed(t *testing.T) {
	fs, req := labelFixture(t, map[string]string{"nato": "CONFIDENTIAL"}, []classification.Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "RESTRICTED"},
	})
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetDelegationEffect() != Effect_EFFECT_ALLOW {
		t.Fatalf("DelegationEffect = %v (%q), want ALLOW: RESTRICTED is under a CONFIDENTIAL cap",
			resp.GetDelegationEffect(), resp.GetDelegationReason())
	}
}

// R2/R7: no rule matched means NO label, and a configured cap then denies.
// The reason has to say the cap could not be EVALUATED, not that a level
// exceeded it — an operator acts on those differently, and the difference
// between "add a rule" and "raise the cap" is the whole of R7's operator
// guidance.
func TestDecide_UnmatchedResourceDeniesWithAnUncheckableReason(t *testing.T) {
	fs, req := labelFixture(t, map[string]string{"nato": "CONFIDENTIAL"}, []classification.Rule{
		{Prefix: "/elsewhere/", Hierarchy: "nato", Level: "UNCLASSIFIED"},
	})
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetDelegationEffect() != Effect_EFFECT_DENY {
		t.Fatalf("DelegationEffect = %v (%q), want DENY: an unmatched resource has no label and the cap "+
			"cannot be evaluated (R2/R7) — no default level, no fallback",
			resp.GetDelegationEffect(), resp.GetDelegationReason())
	}
	if !strings.Contains(resp.GetDelegationReason(), "cannot be evaluated") {
		t.Errorf("DelegationReason = %q, want the uncheckable-cap wording", resp.GetDelegationReason())
	}
	if strings.Contains(resp.GetDelegationReason(), "exceeds") {
		t.Errorf("DelegationReason = %q, want it distinguishable from an ordinary cap violation",
			resp.GetDelegationReason())
	}
}

// The catch-all (R7) labels every resource — but a call that names no
// resource at all has none to label. Resolve would happily match the empty
// prefix against the empty id; doing so here would invent a fact about a
// resource nobody identified, and under a PUBLIC catch-all that fact ALLOWS.
// Skipping is the strictly fail-closed direction: unlabelled denies.
func TestDecide_NoResourceIDMeansNoLabelEvenUnderACatchAll(t *testing.T) {
	fs, req := labelFixture(t, map[string]string{"nato": "CONFIDENTIAL"}, []classification.Rule{
		{Prefix: "", Hierarchy: "nato", Level: "UNCLASSIFIED"},
	})
	req.RawInput = `{"unregistered_field":"/data/reports/q3.pdf"}` // the catalog's "path" is absent
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetDelegationEffect() != Effect_EFFECT_DENY {
		t.Fatalf("DelegationEffect = %v (%q), want DENY: a call carrying no resource identity must not be "+
			"labelled by the empty-prefix catch-all", resp.GetDelegationEffect(), resp.GetDelegationReason())
	}
}

// C1, the lever behind the claim: a tool with no catalog row must not be
// labelled at all, because on that path resource["id"] is a string the caller
// simply typed. Nothing ties it to raw_input, so R4's "the id is what the tool
// actually acts on — lying does not pay" does not hold for it, and resolving
// the tenant's rules against it let a caller pick its own classification by
// naming a decoy.
//
// Two rules, and the decoy is the PERMISSIVE one: before the fix this
// allowed, with the resource labelled UNCLASSIFIED purely because the caller
// asked for that string. Unlabelled denies (R2), which is the same answer
// this path gave before rules existed.
func TestDecide_UncatalogedToolCannotLabelItselfByNamingAnID(t *testing.T) {
	fs, req := wellFormedFixture() // deliberately no catalog row for "Bash"
	fs.chain[0].ClassificationCaps = map[string]string{"nato": "CONFIDENTIAL"}
	fs.labelRules = []classification.Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/public/", Hierarchy: "nato", Level: "UNCLASSIFIED"},
	}
	req.RawInput = `{"path":"/data/secret.txt"}`            // what the tool would act on
	req.Resource = map[string]string{"id": "/public/decoy"} // what the caller claims it is
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetDelegationEffect() != Effect_EFFECT_DENY {
		t.Fatalf("DelegationEffect = %v (%q), want DENY: a caller-typed id is not an identity this PDP "+
			"derived, so no rule may label it — naming /public/decoy must not buy an UNCLASSIFIED label",
			resp.GetDelegationEffect(), resp.GetDelegationReason())
	}
	if !strings.Contains(resp.GetDelegationReason(), "cannot be evaluated") {
		t.Errorf("DelegationReason = %q, want the uncheckable-cap wording: the resource is unlabelled, not "+
			"labelled from the caller's claim", resp.GetDelegationReason())
	}
}

// The mirror, and the one that says the fix is a provenance rule rather than
// a blanket refusal: once the tenant catalogs the tool, the label follows the
// id the PDP extracted from raw_input, and the wire's competing id is inert.
//
// Defence in depth, and credited as such rather than as a mutation kill: NO
// single mutation reaches this, because two independent mechanisms already
// guarantee it on the cataloged path — ApplyExtraction replaces the resource
// map wholesale, AND labelResource resolves the parameter rather than the map.
// Mutating either alone leaves this passing; both together (mutant M21) is
// what it fails on. Kept because that pair is exactly the end-to-end
// guarantee a reader asks about, and because a future change that moved
// labelling back onto the map would be reviewed against ApplyExtraction's
// replacement as its only remaining guard.
func TestDecide_CatalogedToolLabelsTheExtractedIDNotTheWireID(t *testing.T) {
	fs, req := labelFixture(t, map[string]string{"nato": "CONFIDENTIAL"}, []classification.Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/public/", Hierarchy: "nato", Level: "UNCLASSIFIED"},
	})
	req.RawInput = `{"path":"/data/reports/q3.pdf"}`
	req.Resource = map[string]string{"id": "/public/decoy"}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetDelegationEffect() != Effect_EFFECT_DENY {
		t.Fatalf("DelegationEffect = %v (%q), want DENY on the SECRET label of the extracted path",
			resp.GetDelegationEffect(), resp.GetDelegationReason())
	}
	if !strings.Contains(resp.GetDelegationReason(), "SECRET") {
		t.Errorf("DelegationReason = %q, want the extracted path's own label to have decided",
			resp.GetDelegationReason())
	}
}

// wantLogFields asserts each key=value pair appears in the captured log.
//
// key=VALUE pairs, not bare values, and that is the fix for a real hole: the
// lowering line's overridden prefix is BY CONSTRUCTION a prefix of the
// winner's — a shorter rule that matched the same id — so no choice of
// fixture can make Contains(line, "/data/") fail when the line prints
// rule_prefix=/data/public/ and nothing else. Asserting the field NAME
// alongside the value is what pins the second rule; asserting the value
// alone pins nothing, and a mutation deleting overrides_prefix outright
// survived the earlier version of these tests.
func wantLogFields(t *testing.T, line string, fields ...string) {
	t.Helper()
	for _, f := range fields {
		if !strings.Contains(line, f) {
			t.Errorf("log is missing %s — an operator must be able to find both rules by field.\ngot: %s", f, line)
		}
	}
}

// R6 end to end: the carve-out is HONOURED — longest prefix wins, and a
// public file inside a secret directory is genuinely public — and it is
// LOGGED, because a mistyped narrow rule that silently lowers a subtree is
// the mirror risk, and this line is the operator's only signal.
//
// The second half is the security property: the line names the RULES and
// never the resource. Rule prefixes are operator-authored configuration; the
// resource id is derived from client-supplied raw_input, and process logs are
// shipped places an authorization decision's subject matter should not go.
// The adversarial id below is what a mutation that logged it would leak.
func TestDecide_LoweringCarveOutIsHonouredAndLoggedWithoutTheResourceID(t *testing.T) {
	const adversarialID = "/data/public/AKIAIOSFODNN7EXAMPLE-secret.txt"
	fs, req := labelFixture(t, map[string]string{"nato": "CONFIDENTIAL"}, []classification.Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/data/public/", Hierarchy: "nato", Level: "UNCLASSIFIED"},
	})
	req.RawInput = `{"path":"` + adversarialID + `"}`
	logs := captureLogs(t)
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetDelegationEffect() != Effect_EFFECT_ALLOW {
		t.Fatalf("DelegationEffect = %v (%q), want ALLOW: the carve-out lowers the label to UNCLASSIFIED, "+
			"which is under the cap — longest prefix wins (R6)",
			resp.GetDelegationEffect(), resp.GetDelegationReason())
	}

	line := logs.String()
	wantLogFields(t, line,
		"rule_prefix=/data/public/", "rule_hierarchy=nato", "rule_level=UNCLASSIFIED",
		"overrides_prefix=/data/", "overrides_hierarchy=nato", "overrides_level=SECRET")
	if strings.Contains(line, adversarialID) || strings.Contains(line, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("log leaked the resource id: %q", line)
	}
}

// A carve-out that does NOT lower is not logged. R6 asks for the one case
// worth seeing; logging every carve-out would bury it, and this is what fails
// if the report is ever widened to "a longer rule matched".
func TestDecide_RaisingCarveOutIsNotLogged(t *testing.T) {
	fs, req := labelFixture(t, map[string]string{"nato": "TOP-SECRET"}, []classification.Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "RESTRICTED"},
		{Prefix: "/data/reports/", Hierarchy: "nato", Level: "SECRET"},
	})
	logs := captureLogs(t)
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	if _, err := srv.Decide(context.Background(), req); err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if strings.Contains(logs.String(), "carve-out") {
		t.Errorf("a raising carve-out must not be logged as one: %q", logs.String())
	}
}

// R10, end to end and in the operator's log: a commercial carve-out under a
// nato rule escapes the nato cap entirely, ALLOWS, and says so as its own
// line — never as a lowering, which would be a false claim in R6's signal.
func TestDecide_HierarchySwitchIsAllowedAndLoggedAsItsOwnLine(t *testing.T) {
	fs, req := labelFixture(t, map[string]string{"nato": "CONFIDENTIAL"}, []classification.Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "TOP-SECRET"},
		{Prefix: "/data/reports/", Hierarchy: "commercial", Level: "PUBLIC"},
	})
	logs := captureLogs(t)
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetDelegationEffect() != Effect_EFFECT_ALLOW {
		t.Fatalf("DelegationEffect = %v (%q), want ALLOW: a nato cap says nothing about commercial",
			resp.GetDelegationEffect(), resp.GetDelegationReason())
	}

	line := logs.String()
	wantLogFields(t, line,
		"rule_prefix=/data/reports/", "rule_hierarchy=commercial", "rule_level=PUBLIC",
		"overrides_prefix=/data/", "overrides_hierarchy=nato", "overrides_level=TOP-SECRET")
	if strings.Contains(line, "lower") {
		t.Errorf("log = %q, must not claim a lowering: no ordering ranks a commercial level against a "+
			"nato one", line)
	}
}

// I1 end to end: the outer rule's level is one character wrong, so it can
// never be ranked and never lowers anything — the carve-out allows under a
// cap and, before this line existed, said nothing. The rule is inert and only
// the PDP is in a position to notice.
func TestDecide_InertRuleBeneathACarveOutIsLogged(t *testing.T) {
	fs, req := labelFixture(t, map[string]string{"nato": "CONFIDENTIAL"}, []classification.Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "SEKRET"},
		{Prefix: "/data/reports/", Hierarchy: "nato", Level: "UNCLASSIFIED"},
	})
	logs := captureLogs(t)
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetDelegationEffect() != Effect_EFFECT_ALLOW {
		t.Fatalf("DelegationEffect = %v (%q), want ALLOW: the carve-out is UNCLASSIFIED, under the cap",
			resp.GetDelegationEffect(), resp.GetDelegationReason())
	}

	line := logs.String()
	wantLogFields(t, line,
		"rule_prefix=/data/reports/", "rule_level=UNCLASSIFIED",
		"overrides_prefix=/data/", "overrides_hierarchy=nato", "overrides_level=SEKRET")
	if !strings.Contains(line, "cannot rank") {
		t.Errorf("log = %q, want it to say the covered rule cannot be ranked", line)
	}
	if strings.Contains(line, "lower") {
		t.Errorf("log = %q, must not claim a lowering: SEKRET has no rank to have been lowered from", line)
	}
}

// R9 through the whole decision path, on the input that makes it reachable: a
// tenant's own row, one typed character off. The carve-out wins on length, no
// cap names "natoo", and before R9 CheckCap allowed — a capped resource
// becoming an unconditional allow, with R6's log silent too because an
// unrankable hierarchy has no rank to compare.
func TestDecide_UnknownHierarchyInARuleDeniesAndNamesIt(t *testing.T) {
	fs, req := labelFixture(t, map[string]string{"nato": "CONFIDENTIAL"}, []classification.Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/data/reports/", Hierarchy: "natoo", Level: "UNCLASSIFIED"},
	})
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetDelegationEffect() != Effect_EFFECT_DENY {
		t.Fatalf("DelegationEffect = %v (%q), want DENY: a label the system cannot rank is unreadable, "+
			"not permissive (R9/D10)", resp.GetDelegationEffect(), resp.GetDelegationReason())
	}
	if !strings.Contains(resp.GetDelegationReason(), "natoo") {
		t.Errorf("DelegationReason = %q, want it to name the unknown hierarchy — an operator cannot find a "+
			"one-character typo from a bare denial", resp.GetDelegationReason())
	}
}

// R2's boundary, restated for this task: a delegation with NO caps places no
// classification restriction and never did, so the tenant's rules cannot
// change its outcome in either direction. This is the difference between
// shipping labelling and shipping a change that denies more.
func TestDecide_UncappedDecisionIsUnaffectedByTheLabelRules(t *testing.T) {
	fs, req := labelFixture(t, nil, []classification.Rule{
		{Prefix: "", Hierarchy: "nato", Level: "TOP-SECRET"},
	})
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetDelegationEffect() != Effect_EFFECT_ALLOW {
		t.Fatalf("DelegationEffect = %v (%q), want ALLOW: a delegation with no caps is unrestricted on "+
			"this axis regardless of what the resource is labelled",
			resp.GetDelegationEffect(), resp.GetDelegationReason())
	}
}

// R1, enforced where it can be: the wire's own classification and hierarchy
// are never believed. cmd/stratium-pep does not send them, but
// DecideRequest.resource is a caller-supplied map that survives unchanged for
// an uncataloged tool, so "no PEP in this repo does it" is not the guarantee
// — this is. A client asserting its own classification is D1 relocated, and
// it would be the cheapest possible cap bypass.
//
// No catalog row and no rules: the wire's PUBLIC claim is the ONLY thing that
// could make this allow.
func TestDecide_WireSuppliedClassificationIsNeverBelieved(t *testing.T) {
	fs, req := wellFormedFixture()
	fs.chain[0].ClassificationCaps = map[string]string{"nato": "CONFIDENTIAL"}
	req.Resource = map[string]string{
		"id":             "/data/reports/q3.pdf",
		"classification": "UNCLASSIFIED",
		"hierarchy":      "nato",
	}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetDelegationEffect() != Effect_EFFECT_DENY {
		t.Fatalf("DelegationEffect = %v (%q), want DENY: a caller-supplied classification must never "+
			"satisfy a cap", resp.GetDelegationEffect(), resp.GetDelegationReason())
	}
	if !strings.Contains(resp.GetDelegationReason(), "cannot be evaluated") {
		t.Errorf("DelegationReason = %q, want the uncheckable-cap wording — accepting any non-ALLOW would "+
			"pass on an ESCALATE or on a denial from some other leg's rule entirely",
			resp.GetDelegationReason())
	}
}

// The same claim, losing to a real rule rather than to its absence: the
// tenant's rules decide, and a wire claim cannot even soften them.
func TestDecide_WireSuppliedClassificationLosesToTheTenantsRule(t *testing.T) {
	fs, req := labelFixture(t, map[string]string{"nato": "CONFIDENTIAL"}, []classification.Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
	})
	req.Resource = map[string]string{"classification": "UNCLASSIFIED", "hierarchy": "nato"}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetDelegationEffect() != Effect_EFFECT_DENY {
		t.Fatalf("DelegationEffect = %v (%q), want DENY on the tenant's own SECRET label",
			resp.GetDelegationEffect(), resp.GetDelegationReason())
	}
	if !strings.Contains(resp.GetDelegationReason(), "SECRET") {
		t.Errorf("DelegationReason = %q, want the tenant's rule to be what decided", resp.GetDelegationReason())
	}
}

// Fail closed, and audited like every other pre-decision denial. The argument
// is the tool catalog's, sharpened: a rules table that exists but could not be
// read might hold the one row that labels this resource, and proceeding as
// though the tenant had none turns a database blip into an unlabelled — and
// under R2 therefore denied — resource with no record of why.
func TestDecide_ResourceLabelRuleLoadFailureDeniesAndAudits(t *testing.T) {
	fs, req := labelFixture(t, map[string]string{"nato": "CONFIDENTIAL"}, nil)
	fs.labelRulesErr = errors.New("connection reset")
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v, want a decision (fail closed, not a bare RPC error)", err)
	}
	if resp.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
	}
	if !strings.Contains(resp.GetReason(), "resource label rules") {
		t.Errorf("Reason = %q, want it to name the resource label rule load failure", resp.GetReason())
	}
	if len(fs.appended) != 1 {
		t.Errorf("audit entries appended = %d, want 1: a pre-decision denial is audited like any other",
			len(fs.appended))
	}
}
