package authz

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"stratium/pkg/models"
)

var (
	// ErrUnknownAction is returned when an action cannot be classified and the
	// tenant has configured unknown actions to deny.
	ErrUnknownAction = errors.New("action could not be classified")

	// ErrOverrideLowersTier is returned when an override would reduce an
	// action's sensitivity below its built-in tier. Overrides are raise-only.
	ErrOverrideLowersTier = errors.New("tier override may not lower the built-in tier")
)

// TierTable is a tenant's resolved tier configuration, loaded by the caller.
type TierTable struct {
	// Overrides are tenant-authored and meant to be raise-only. That
	// invariant is enforced only at write time — by ValidateOverride, if the
	// write path calls it, and by the tier_overrides_raise_only DB CHECK,
	// which compares against a caller-supplied builtin_tier column rather
	// than recomputing BuiltinTier(). Neither holds on the decision path
	// below: DeriveTier consults Overrides first and returns whatever is
	// stored, without re-deriving or re-validating against the builtin.
	// TODO(phase-2): close the gap — either have DeriveTier reject an
	// override below the live BuiltinTier(), or guarantee every write path
	// is ValidateOverride-gated and builtin_tier cannot drift out of sync.
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
// Raw input is classified first and takes precedence: the verb attached to a
// shell call says nothing about what the command does.
func BuiltinTier(a Action) (models.ActionTier, bool) {
	if a.RawInput != "" {
		// Match against the normalized form so quoting and ${IFS} cannot break
		// the adjacency the patterns rely on. Check the raw form too:
		// normalization only ever adds matches, never removes them.
		norm := normalizeCommand(a.RawInput)
		matches := func(re *regexp.Regexp) bool {
			return re.MatchString(a.RawInput) || re.MatchString(norm)
		}
		switch {
		case matches(reDestructive):
			return models.ActionTierDestructive, true
		case matches(reSQLContext) && matches(reDestructiveSQL):
			return models.ActionTierDestructive, true
		case matches(reExternal):
			return models.ActionTierExternalComms, true
		case reCompound.MatchString(a.RawInput):
			// Compound: the leading token is not the whole story, so READ_ONLY
			// is not available. Destructive and external already had their say.
			return models.ActionTierInternalModify, true
		case reReadOnly.MatchString(a.RawInput):
			return models.ActionTierReadOnly, true
		default:
			// An unrecognized command is assumed to modify. It is not read-only
			// merely because no pattern matched.
			return models.ActionTierInternalModify, true
		}
	}
	if t, ok := verbTiers[strings.ToLower(a.Verb)]; ok {
		return t, true
	}
	return models.ActionTierReasoning, false
}

// DeriveTier resolves an action's sensitivity server-side (spec §4.4):
//
//  1. tenant override  2. catalog entry  3. built-in  4. floor, or deny
//
// The caller's declared tier is never consulted here.
func DeriveTier(t TierTable, a Action) (models.ActionTier, error) {
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

// ValidateOverride enforces the raise-only invariant. Called when an
// administrator writes an override, not on the decision path.
func ValidateOverride(builtin, override models.ActionTier) error {
	if override < builtin {
		return fmt.Errorf("%w: built-in is %s, override is %s",
			ErrOverrideLowersTier, builtin, override)
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
