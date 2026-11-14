package authz

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/stratiumdata/stratium/pkg/models"
)

var (
	// ErrUnknownAction is returned when an action cannot be classified and the
	// tenant has configured unknown actions to deny.
	ErrUnknownAction = errors.New("action could not be classified")

	// ErrOverrideLowersTier is returned when an override would reduce an
	// action's sensitivity below the resolution beneath it — the tenant's own
	// tool_catalog entry where one exists, the built-in classification
	// otherwise (OverrideBaseline). Overrides are raise-only.
	//
	// The message says "the resolution beneath it", not "the built-in tier",
	// and the difference reaches an operator: cmd/stratium-pap/respond.go
	// writes this text straight into a 400 body. Naming the built-in there
	// sends someone who raised a tool in tool_catalog off to check a tier
	// that is not the one blocking them.
	ErrOverrideLowersTier = errors.New("tier override may not lower the resolution beneath it")
)

// TierTable is a tenant's resolved tier configuration, loaded by the caller.
type TierTable struct {
	// Overrides are the tenant's raise-only corrections, keyed by the same
	// lookupKeys as Catalog. deriveTierByName consults them first and returns
	// whatever is stored, without re-deriving — so whether a lowering row can
	// ever appear in this map is entirely the caller's responsibility, and as
	// of Phase 14 Task 7 it is enforced at both ends of the row's life:
	//
	//   - Write time: store.CreateTierOverride/UpdateTierOverride compute
	//     OverrideBaseline against the tenant's own live merged catalog and
	//     call ValidateOverride before the INSERT/UPDATE lands.
	//   - Read time: pdpgrpc.Decide re-runs that identical check against the
	//     catalog it has just loaded for this decision, and DROPS any row
	//     that fails it before ever putting it in this map.
	//
	// The read-time half is the one that cannot be bypassed, and it is not
	// redundant with either the write-time call or the schema's own
	// tier_overrides_raise_only CHECK: that CHECK compares action_tier
	// against a stored builtin_tier column, which a direct INSERT as a
	// database superuser supplies for itself, and which goes stale the
	// moment the tenant's tool_catalog changes underneath it. Re-validating
	// on read is what makes this map's raise-only claim true rather than
	// merely intended.
	//
	// A dropped row is dropped, never failed on: resolution falls through to
	// the (higher, therefore safer) tier beneath it, so one bad row costs the
	// tenant that one override, not every decision.
	Overrides map[string]models.ActionTier

	// Catalog holds tiers registered with a tool at registration time.
	Catalog map[string]models.ActionTier

	// UnknownTier is the floor for unclassifiable actions when DenyUnknown is false.
	UnknownTier models.ActionTier

	// DenyUnknown makes an unclassifiable action an error rather than a floor.
	DenyUnknown bool
}

// Shell patterns, most severe first.
//
// RESIDUAL RISK, stated plainly: matching strings is a heuristic, not a
// boundary. An adversary who controls the command text can eventually defeat
// any static classifier — base64-piped-to-sh is the trivial existence proof.
// The real controls are the delegation ceiling, the agent's tool allowlist,
// and escalation; this function's job is to stop an action being *accidentally*
// or *casually* under-rated, not to withstand a determined attacker.
// See spec §4.4.
var (
	reDestructive = regexp.MustCompile(`(?i)\brm\s+-[a-z]*[rf]|\bmkfs\b|\bdd\s+if=|\bshred\b|` +
		// DROP must cover every object type, not just the three that store rows.
		// DROP TRIGGER audit_chain_no_truncate is exactly the statement that
		// defeats the audit table's append-only protection, and it was rated
		// INTERNAL_MODIFY before this alternation was widened.
		`\bdropdb\b|\bdropuser\b|\btruncate\s+-s\b|` +
		`\bgit\s+push\s+--force|\bkubectl\s+delete\b|\bterraform\s+destroy\b`)

	// SQL keywords only count when something is actually talking to a database.
	// Applied unscoped, `\bREVOKE\b` and `\bALTER\s+(TABLE|ROLE|USER)\b` match
	// ordinary English: `git commit -m "revoke stale session tokens"` rated
	// DESTRUCTIVE. That is the safe direction, but it pressures operators into
	// widening delegations to get work done, which trades a loud annoyance for a
	// quiet weakening. Scoping keeps the detections that matter —
	// `psql -c 'DROP TRIGGER audit_chain_no_truncate ...'` still rates
	// DESTRUCTIVE — without the prose collisions.
	reSQLContext = regexp.MustCompile(`(?i)\b(psql|mysql|mariadb|sqlite3?|sqlcmd|` +
		`pgcli|mycli|sqlplus|clickhouse-client|cockroach\s+sql|` +
		`pg_dump|pg_restore|flyway|liquibase|migrate)\b`)

	reDestructiveSQL = regexp.MustCompile(`(?i)` +
		`\bDROP\s+(TABLE|DATABASE|SCHEMA|TRIGGER|RULE|ROLE|USER|FUNCTION|INDEX|VIEW|OWNED|POLICY)\b|` +
		`\bTRUNCATE\b|\bREVOKE\b|\bALTER\s+(TABLE|ROLE|USER)\b|\bDELETE\s+FROM\b`)

	reExternal = regexp.MustCompile(`(?i)\b(curl|wget|ssh|scp|rsync|nc|telnet)\b|` +
		`\bgit\s+push\b|\bdocker\s+push\b|\bnpm\s+publish\b|\b(aws|gcloud|az)\s`)

	reReadOnly = regexp.MustCompile(`(?i)^\s*(cat|ls|pwd|head|tail|wc|grep|find|file|stat|` +
		`echo|which|whoami|date|df|du|ps|env|` +
		`git\s+(log|status|diff|show|branch)|docker\s+ps|kubectl\s+get)\b`)

	// A string containing any of these is not a single command, so its leading
	// token says nothing about what it does. `ls; "rm" -rf /` led with `ls` and
	// was rated READ_ONLY — three tiers below the truth.
	reCompound = regexp.MustCompile("[;&|\n\r`]|\\$\\(")
)

// normalizeCommand strips the punctuation an attacker uses to break token
// adjacency, so `"rm" -rf /` and `rm${IFS}-rf /` match the same patterns as
// `rm -rf /`. Quotes are removed rather than parsed — this is a matching aid,
// not a shell lexer, and over-normalizing is safe here because the result is
// only ever used to raise a tier, never to lower one.
func normalizeCommand(s string) string {
	s = strings.NewReplacer(`"`, "", `'`, "", "\\", "").Replace(s)
	s = strings.ReplaceAll(s, "${IFS}", " ")
	s = strings.ReplaceAll(s, "$IFS", " ")
	return strings.Join(strings.Fields(s), " ")
}

var verbTiers = map[string]models.ActionTier{
	"read": models.ActionTierReadOnly, "get": models.ActionTierReadOnly,
	"list": models.ActionTierReadOnly, "query": models.ActionTierReadOnly,
	"search": models.ActionTierReadOnly,

	"write": models.ActionTierInternalModify, "create": models.ActionTierInternalModify,
	"update": models.ActionTierInternalModify, "modify": models.ActionTierInternalModify,
	"patch": models.ActionTierInternalModify,

	"send": models.ActionTierExternalComms, "email": models.ActionTierExternalComms,
	"notify": models.ActionTierExternalComms, "webhook": models.ActionTierExternalComms,
	"publish": models.ActionTierExternalComms,

	"delete": models.ActionTierDestructive, "destroy": models.ActionTierDestructive,
	"drop": models.ActionTierDestructive, "revoke": models.ActionTierDestructive,
	"transfer": models.ActionTierDestructive, "execute": models.ActionTierDestructive,
}

// BuiltinTier classifies an action using the shipped defaults, returning false
// when the action is unrecognized.
//
// Shell input is classified first and takes precedence over the verb: the
// verb attached to a shell call says nothing about what the command does.
//
// When both RawInput and NormalizedInput are set, they are combined by
// evidence, not by severity:
//
//  1. If RawInput positively matches a destructive or external pattern,
//     that tier stands and is never lowered — this is what stops a lying or
//     buggy PEP from hiding "rm -rf /" behind a claimed-safe extraction.
//  2. Otherwise, if NormalizedInput positively classifies (matches some
//     pattern rather than falling through to classifyInput's "unrecognized
//     -> assume it modifies" default), its tier is used.
//  3. Otherwise, RawInput's own result is used, including its default.
//
// A positive pattern match is evidence; falling through to the default is
// not. Taking the plain maximum of the two — the previous rule — conflated
// them: an opaque JSON RawInput blob (e.g. {"command":"ls -la"}) never
// positively matches anything, so it always fell to the INTERNAL_MODIFY
// default, and INTERNAL_MODIFY outranks READ_ONLY. That let the
// worse-informed default override a correct, more specific NormalizedInput
// extraction, flooring every read at tier 2 regardless of what
// NormalizedInput said. See tier_test.go's NormalizedInputComposes* cases
// and docs/superpowers/plans/2026-08-10-phase-3b-normalized-input.md.
func BuiltinTier(a Action) (models.ActionTier, bool) {
	var rawTier models.ActionTier
	var haveRaw bool
	if a.RawInput != "" {
		rawTier, _ = classifyInput(a.RawInput)
		haveRaw = true
	}

	// Step 1: a positive destructive-or-external match on raw is final.
	// DeriveTier applies this same rule above every name-keyed lookup; it is
	// kept here too because BuiltinTier is exported and callable directly.
	if evidence, ok := destructiveEvidence(a); ok {
		return evidence, true
	}

	// Step 2: a normalized input that positively classifies wins.
	if a.NormalizedInput != "" {
		if normTier, normMatched := classifyInput(a.NormalizedInput); normMatched {
			return normTier, true
		}
	}

	// Step 3: raw's own result, including its default.
	if haveRaw {
		return rawTier, true
	}
	if t, ok := verbTiers[strings.ToLower(a.Verb)]; ok {
		return t, true
	}
	return models.ActionTierReasoning, false
}

// classifyInput applies the shell-pattern heuristics to a single input
// string, reporting both the tier and whether a pattern was positively
// matched (evidence) as opposed to falling through to the "unrecognized ->
// assume it modifies" default (absence of evidence) — BuiltinTier's
// combining rule treats those two cases differently. BuiltinTier calls this
// once for RawInput and once for NormalizedInput — the logic itself does
// not know or care which one it was handed.
func classifyInput(s string) (tier models.ActionTier, matched bool) {
	// Match against the normalized form so quoting and ${IFS} cannot break
	// the adjacency the patterns rely on. Check the raw form too:
	// normalization only ever adds matches, never removes them.
	norm := normalizeCommand(s)
	matches := func(re *regexp.Regexp) bool {
		return re.MatchString(s) || re.MatchString(norm)
	}
	switch {
	case matches(reDestructive):
		return models.ActionTierDestructive, true
	case matches(reSQLContext) && matches(reDestructiveSQL):
		return models.ActionTierDestructive, true
	case matches(reExternal):
		return models.ActionTierExternalComms, true
	case reCompound.MatchString(s):
		// Compound: the leading token is not the whole story, so READ_ONLY
		// is not available. Destructive and external already had their say.
		return models.ActionTierInternalModify, true
	case reReadOnly.MatchString(s):
		return models.ActionTierReadOnly, true
	default:
		// An unrecognized string is assumed to modify. It is not read-only
		// merely because no pattern matched — and that assumption is not
		// evidence, so matched is false.
		return models.ActionTierInternalModify, false
	}
}

// DeriveTier resolves an action's sensitivity server-side (spec §4.4):
//
//  1. tenant override  2. catalog entry  3. built-in  4. floor, or deny
//
// The caller's declared tier is never consulted here.
// destructiveEvidence reports a positive destructive-or-external pattern match
// on a's raw input. It is the one signal in this package derived from what the
// caller actually sent rather than from what it named the call, which is why
// no name-keyed lookup may lower it.
//
// Raw only, never NormalizedInput: normalization is the PEP's extraction, and
// a PEP willing to mislabel a call is equally willing to extract wrongly. Raw
// is the field a bad PEP cannot launder, which is the entire basis of Phase
// 3b's design argument.
func destructiveEvidence(a Action) (models.ActionTier, bool) {
	if a.RawInput == "" {
		return models.ActionTierReasoning, false
	}
	tier, matched := classifyInput(a.RawInput)
	if !matched {
		return models.ActionTierReasoning, false
	}
	if tier != models.ActionTierDestructive && tier != models.ActionTierExternalComms {
		return models.ActionTierReasoning, false
	}
	return tier, true
}

// DeriveTier resolves an action's sensitivity tier server-side (spec §4.4):
// tenant overrides, then the tool catalog, then the built-in classifier.
//
// Above all three sits one rule: a positive destructive-or-external match on
// raw input is evidence and is never lowered. Overrides and catalog entries
// are keyed on a tool NAME, so without this a PEP could pick a benign name for
// a hostile call and choose its own tier — spec defect D1 by another route.
// Phase 3b established the rule but implemented it inside BuiltinTier; Phase
// 3c then added the catalog lookup above BuiltinTier and the rule silently
// stopped applying to every catalogued name. It lives here now, at the single
// boundary every caller routes through, so a fourth lookup layer cannot repeat
// that.
//
// Evidence only ever raises. A tenant override or catalog entry HIGHER than
// the evidence stands unchanged, which keeps the raise-only override rule
// (ValidateOverride) intact.
func DeriveTier(t TierTable, a Action) (models.ActionTier, error) {
	tier, err := deriveTierByName(t, a)
	if err != nil {
		// DenyUnknown already denies; evidence cannot make that safer.
		return tier, err
	}
	if evidence, ok := destructiveEvidence(a); ok && evidence > tier {
		return evidence, nil
	}
	return tier, nil
}

// deriveTierByName is DeriveTier's name-keyed resolution, without the evidence
// rule. It exists only so DeriveTier can apply that rule to every branch at
// once instead of at each return.
func deriveTierByName(t TierTable, a Action) (models.ActionTier, error) {
	keys := lookupKeys(a)
	for _, k := range keys {
		if tier, ok := t.Overrides[k]; ok {
			return tier, nil
		}
	}
	for _, k := range keys {
		if tier, ok := t.Catalog[k]; ok {
			return tier, nil
		}
	}
	if tier, ok := BuiltinTier(a); ok {
		return tier, nil
	}
	if t.DenyUnknown {
		return models.ActionTierReasoning,
			fmt.Errorf("%w: tool=%q verb=%q", ErrUnknownAction, a.Tool, a.Verb)
	}
	return t.UnknownTier, nil
}

// lookupKeys returns candidate keys, most specific first, so a tenant may
// override a whole tool ("Bash") or a single verb ("read").
func lookupKeys(a Action) []string {
	keys := make([]string, 0, 3)
	if a.Tool != "" && a.Verb != "" {
		keys = append(keys, a.Tool+":"+a.Verb)
	}
	if a.Tool != "" {
		keys = append(keys, a.Tool)
	}
	if a.Verb != "" {
		keys = append(keys, strings.ToLower(a.Verb))
	}
	return keys
}

// OverrideBaseline is the tier an override on key may not fall below: what
// deriveTierByName would resolve that key to with the override itself
// removed — the tenant's catalog entry where one exists, the built-in
// otherwise, and ActionTier's own floor when neither knows the key.
//
// catalog is the merged map BuildTierCatalog produces, not DefaultCatalog()
// alone. That is the whole correction Phase 14 Task 7 makes: the write path
// compared against DefaultCatalog()+verbTiers only, which predates Phase 8's
// per-tenant catalog, so built-in READ_ONLY + catalog DESTRUCTIVE + override
// WRITE passed validation (WRITE >= READ_ONLY) and then LOWERED the
// effective tier from DESTRUCTIVE to WRITE — a lowering that satisfied the
// raise-only rule by comparing against the wrong thing.
//
// A NULL-tier catalog row (Bash-shaped: "no fixed tier, classify by
// command") contributes no entry to the merged map at all (BuildTierCatalog's
// own doc comment), so a key naming one falls through to the built-in branch
// here rather than being refused for having no static baseline. That is a
// deliberate ruling, not an oversight: refusing would block an operator
// raising Bash to DESTRUCTIVE tenant-wide, which is the single most
// legitimate override this table exists for. The residual it leaves is real
// and worth stating — a static override on a command-derived entry replaces
// per-command classification for that tool, and only DeriveTier's own
// evidence rule (destructiveEvidence, §4.4.1) still binds above it, which it
// does unconditionally and regardless of what any override claims.
//
// One key can be reached by several DIFFERENT actions, so the baseline is the
// MAXIMUM over all of them, computed by handing each to deriveTierByName —
// the real resolution function, not a re-derivation of its precedence. A key
// that clears the highest of them cannot lower any of them.
//
// # Which actions, and why the set is small
//
// Action.Verb has exactly ONE production writer: ApplyExtraction (extract.go),
// which copies the tenant's tool_catalog.verb for the tool being called. It is
// not caller-supplied — Task 3 retired it from the wire — so the verb a tool
// can arrive with is a FUNCTION of the tool name, not a free value. That is
// what makes this enumerable rather than a maximisation over every verb in
// verbTiers, and it is why entries, not just the merged catalog map, has to be
// passed in: the merged map has dropped the verb column.
//
// So the actions a stored key can govern are, exactly:
//
//  1. key as a whole tool name — {Tool: key, Verb: verbOf(key)}.
//  2. key as a verb — every catalogued tool whose own verb lowercases to key.
//     lookupKeys lowercases its verb slot and nothing else.
//  3. key as Tool+":"+Verb — every split of key at an interior colon whose
//     tool half actually carries that verb half in the catalog.
//
// Cases 2 and 3 are not symmetric decorations: lookupKeys builds Tool+":"+Verb
// from two unvalidated TEXT columns, so the concatenation is LOSSY —
// "svc:index:delete" is {Tool:"svc:index", Verb:"delete"} and
// {Tool:"svc", Verb:"index:delete"} equally. There is no faithful single
// inverse to pick, so every split the catalog can actually produce is a
// candidate and the strictest wins. deriveTierByName does the lookups rather
// than this function doing them itself, so the case-folding rule has no second
// copy to drift.
//
// # Two baselines, and why one is not enough
//
// The answer is the MAXIMUM of two separate resolutions of the same key:
//
//	sibling-aware — every OTHER stored override applies, this key's does not
//	catalog-only  — no override applies at all
//
// Neither subsumes the other, and dropping either one reopens a real attack.
//
// Sibling-aware alone misses MUTUAL VOUCHING. Two rows can each supply the
// other's baseline and both survive: with catalog Foo=READ_ONLY verb "write",
// write "Foo:write"=READ_ONLY (legitimate, equal to the catalog), then
// "Foo"=READ_ONLY (baseline READ_ONLY via the sibling). Raise the catalog row
// to DESTRUCTIVE afterwards and neither row is dropped, because each is
// measured against the other's STORED tier with no check that the other will
// itself be honored. Both rows are writable through the PAP's own API, in an
// order where each write is individually legitimate when it is made. The
// catalog-only term breaks the cycle: it depends on no override at all, so no
// set of rows can collectively vouch its way past it.
//
// Catalog-only alone misses the SIBLING SHADOW: deriveTierByName probes
// overrides at EVERY slot before any catalog lookup, so a tenant-wide
// "Bash"=DESTRUCTIVE raise sits beneath a new "Bash:read" row — and with a
// NULL-tier Bash catalog entry the catalog-only baseline for "Bash:read" is
// only READ_ONLY (verbTiers), so the lowering row is accepted.
//
// What the maximum buys, as an invariant: an honored override is at or above
// the catalog-only baseline of its own key, and baselineActions enumerates
// every action that key can govern, so no set of honored overrides can resolve
// ANY call below its catalog-only resolution — however the rows refer to each
// other. That is a strict tightening of both rules, so it refuses no override
// either rule alone would have accepted for a legitimate reason. Proven over
// generated input by TestHonoredOverrides_NeverResolveBelowTheCatalog, which
// is a SET-level property: the per-key one cannot express it, because
// measuring each row against the stored set is exactly the premise mutual
// vouching exploits.
//
// # The bound, stated exactly
//
// This bounds the NAME-KEYED resolution: overrides, the catalog, and the
// built-in verb table. It does NOT bound BuiltinTier's classification of
// caller-supplied RawInput, and that one is genuinely unboundable rather than
// merely unimplemented: RawInput is free text from the PEP, so the maximum
// over it is DESTRUCTIVE for every key, which would refuse every override
// anyone could ever write.
//
// The consequence, stated plainly: an override on a name REPLACES per-
// invocation classification for the calls it matches. An override of REASONING
// on an uncatalogued tool does lower what `ls -la` would have classified. That
// is not a hole in this function, it is what an override IS — the same
// residual the NULL-tier Bash ruling above states, in its general form. What
// still binds is DeriveTier's evidence rule, which re-raises DESTRUCTIVE and
// EXTERNAL_COMMS raw input unconditionally, above any override. Pinned by
// TestOverrideBaseline_RawInputClassificationIsNotBounded so it cannot change
// quietly, and generated (not curated) coverage of everything this DOES bound
// lives in TestOverrideBaseline_Property.
func OverrideBaseline(t TierTable, entries []models.ToolCatalogEntry, key string) models.ActionTier {
	// Every OTHER stored override still applies beneath this one; this one
	// does not apply to itself. maps.Clone(nil) is nil and delete on a nil
	// map is a no-op, so a tenant with no other rows needs no special case.
	others := maps.Clone(t.Overrides)
	delete(others, key)

	siblingAware := baselineFrom(TierTable{
		Catalog:     t.Catalog,
		Overrides:   others,
		UnknownTier: t.UnknownTier,
		DenyUnknown: t.DenyUnknown,
	}, entries, key)

	catalogOnly := baselineFrom(TierTable{
		Catalog:     t.Catalog,
		UnknownTier: t.UnknownTier,
		DenyUnknown: t.DenyUnknown,
	}, entries, key)

	if catalogOnly > siblingAware {
		return catalogOnly
	}
	return siblingAware
}

// baselineFrom is one of OverrideBaseline's two resolutions: the highest tier
// beneath resolves for any action key can govern. The two calls differ only in
// what beneath.Overrides holds — see OverrideBaseline for why both are needed.
func baselineFrom(beneath TierTable, entries []models.ToolCatalogEntry, key string) models.ActionTier {
	baseline := beneath.UnknownTier
	for _, a := range baselineActions(entries, key) {
		tier, err := deriveTierByName(beneath, a)
		if err != nil {
			// DenyUnknown only. Skipping is the PERMISSIVE direction, not the
			// safe one — it leaves the baseline lower than this candidate
			// might have made it. It is correct anyway: an action
			// deriveTierByName refuses to classify is denied outright at
			// decision time, so there is no tier for an override to lower.
			continue
		}
		if tier > baseline {
			baseline = tier
		}
	}
	return baseline
}

// baselineActions returns every action that can reach key — the three cases
// enumerated in OverrideBaseline's doc comment. It is lookupKeys read
// backwards: lookupKeys turns an Action into the keys a stored override might
// match, this turns one stored key back into the actions that could match it.
//
// entries is the tenant's catalog rows, not the merged tier map, because the
// verb column is what makes this enumeration finite — see OverrideBaseline.
func baselineActions(entries []models.ToolCatalogEntry, key string) []Action {
	verbOf := func(tool string) string {
		for _, e := range entries {
			if e.ToolName == tool {
				return e.Verb
			}
		}
		return ""
	}

	// 1. key as a whole tool name, carrying whatever verb the catalog gives
	//    that tool (possibly none).
	actions := []Action{{Tool: key, Verb: verbOf(key)}}

	// 2. key as a verb: every tool whose catalogued verb lowercases to it.
	for _, e := range entries {
		if strings.ToLower(e.Verb) == key {
			actions = append(actions, Action{Tool: e.ToolName, Verb: e.Verb})
		}
	}

	// 3. key as Tool+":"+Verb, at each interior colon. The verbOf check keeps
	//    this to splits the catalog can actually produce: a leading or
	//    trailing colon leaves one half empty, and lookupKeys never builds a
	//    composite key from an empty Tool or Verb.
	for i := 1; i < len(key)-1; i++ {
		if key[i] == ':' && verbOf(key[:i]) == key[i+1:] {
			actions = append(actions, Action{Tool: key[:i], Verb: key[i+1:]})
		}
	}
	return actions
}

// ValidateOverride enforces the raise-only invariant: an override may name a
// tier at or above the resolution beneath it, never below.
//
// baseline is what OverrideBaseline computes for the override's own key, and
// both ends of an override's life call this with exactly that — the PAP
// before writing the row (store.CreateTierOverride/UpdateTierOverride) and
// the PDP before honoring it (pdpgrpc.Decide). The comparison itself is
// unchanged since Phase 2 and the first parameter is the same VALUE it
// always should have been; it was named `builtin` until Phase 14 Task 7
// because until then the only caller had no tenant catalog to consult.
// Renamed, not re-specified: what moved is what a correct caller passes.
func ValidateOverride(baseline, override models.ActionTier) error {
	if override < baseline {
		return fmt.Errorf("%w: baseline is %s, override is %s",
			ErrOverrideLowersTier, baseline, override)
	}
	return nil
}

// CheckDeclaredTier compares the caller's declared tier against the derived one.
//
// Over-declaration is permitted — a conservative client that rounds up is not
// attacking anything. Under-declaration is denied: it is an attempt to slip a
// sensitive action beneath a delegation cap, and it is the hole that made
// every enforcement path in the previous system bypassable (spec §1.1 D1).
func CheckDeclaredTier(derived models.ActionTier, declared *models.ActionTier) LegResult {
	if declared == nil {
		return LegResult{Effect: EffectAllow}
	}
	if *declared < derived {
		return LegResult{
			Effect: EffectDeny,
			Reason: fmt.Sprintf("declared action tier %s is below the derived tier %s (under-declaration)",
				*declared, derived),
		}
	}
	return LegResult{Effect: EffectAllow}
}

// DroppedOverride is one stored override row that failed read-time
// re-validation, and the two tiers that explain why. Returned rather than
// logged: internal/authz stays pure, so the caller decides how a dropped row
// is surfaced (pdpgrpc.Decide logs it; the PAP's dry-run endpoint has nothing
// to say about it).
type DroppedOverride struct {
	Key      string
	Override models.ActionTier
	Baseline models.ActionTier
}

// HonoredOverrides is read-time re-validation of §4.4's raise-only rule: it
// splits t.Overrides into the rows a decision may honor and the rows it must
// drop, each measured against OverrideBaseline and compared by the same
// ValidateOverride the PAP's write path calls.
//
// t.Overrides is the STORED set, and every row is measured against all of it
// (minus its own row — OverrideBaseline's doing). Not against the honored
// subset being built: that would make the answer depend on map iteration
// order, which an authorization decision must never do. Soundness does not
// rest on the stored set being trustworthy — OverrideBaseline's catalog-only
// term is what stops a set of rows vouching for each other, and its own doc
// comment carries that argument.
//
// dropped is sorted by key so that two runs over the same rows report the same
// thing in the same order — map iteration alone would not.
//
// Both callers route through here rather than reimplementing the filter:
// pdpgrpc.Decide, which honors the result and logs what it dropped, and the
// PAP's test-input endpoint, which must predict the same decision production
// would make. A second copy of this rule is exactly how the two would drift.
func HonoredOverrides(t TierTable, entries []models.ToolCatalogEntry) (map[string]models.ActionTier, []DroppedOverride) {
	honored := make(map[string]models.ActionTier, len(t.Overrides))
	var dropped []DroppedOverride
	for key, tier := range t.Overrides {
		baseline := OverrideBaseline(t, entries, key)
		if ValidateOverride(baseline, tier) != nil {
			dropped = append(dropped, DroppedOverride{Key: key, Override: tier, Baseline: baseline})
			continue
		}
		honored[key] = tier
	}
	slices.SortFunc(dropped, func(a, b DroppedOverride) int { return strings.Compare(a.Key, b.Key) })
	return honored, dropped
}
