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
	// Overrides are tenant-authored and raise-only, validated by
	// ValidateOverride at write time and by a database CHECK.
	Overrides map[string]models.ActionTier

	// Catalog holds tiers registered with a tool at registration time.
	Catalog map[string]models.ActionTier

	// UnknownTier is the floor for unclassifiable actions when DenyUnknown is false.
	UnknownTier models.ActionTier

	// DenyUnknown makes an unclassifiable action an error rather than a floor.
	DenyUnknown bool
}

// Shell patterns, most severe first.
var (
	reDestructive = regexp.MustCompile(`(?i)\brm\s+-[a-z]*[rf]|\bmkfs\b|\bdd\s+if=|\bshred\b|` +
		`\bDROP\s+(TABLE|DATABASE|SCHEMA)\b|\bTRUNCATE\b|\bdropdb\b|` +
		`\bgit\s+push\s+--force|\bkubectl\s+delete\b|\bterraform\s+destroy\b`)

	reExternal = regexp.MustCompile(`(?i)\b(curl|wget|ssh|scp|rsync|nc|telnet)\b|` +
		`\bgit\s+push\b|\bdocker\s+push\b|\bnpm\s+publish\b|\b(aws|gcloud|az)\s`)

	reReadOnly = regexp.MustCompile(`(?i)^\s*(cat|ls|pwd|head|tail|wc|grep|find|file|stat|` +
		`echo|which|whoami|date|df|du|ps|env|` +
		`git\s+(log|status|diff|show|branch)|docker\s+ps|kubectl\s+get)\b`)
)

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
		switch {
		case reDestructive.MatchString(a.RawInput):
			return models.ActionTierDestructive, true
		case reExternal.MatchString(a.RawInput):
			return models.ActionTierExternalComms, true
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
