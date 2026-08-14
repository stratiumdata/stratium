// role.go resolves an operator's Role from a verified token's claims,
// against a RoleMapping built once at startup from configuration -- N2's
// "roles come from OIDC claims, never a table." There is deliberately no
// database read anywhere in this file (or this binary, this task -- see the
// phase's global "no database access in Task 1" constraint): a roles table
// would need a bootstrap seed, and "who creates the first admin" is how an
// admin plane locks a tenant out of itself on day one. The customer's IdP
// already knows who its administrators are.
package main

import (
	"errors"
	"fmt"
)

// Role is an operator's authorization level on the PAP. The zero value ""
// is deliberately not a valid role -- see meets, and resolveRole's own doc
// comment for why a Role is only ever handed back alongside a nil error.
type Role string

const (
	RoleViewer Role = "viewer"
	RoleEditor Role = "editor"
	RoleAdmin  Role = "admin"
)

// roleRank orders the three roles so meets can compare them. A role absent
// from this map (including the zero value "") ranks 0, below every real
// role -- see TestRole_Meets for why that specific behavior (the zero value
// satisfies no minimum, not even RoleViewer) matters: it is what makes an
// unset Role fail closed by construction rather than by every caller
// remembering to check for it separately.
var roleRank = map[Role]int{
	RoleViewer: 1,
	RoleEditor: 2,
	RoleAdmin:  3,
}

// meets reports whether r carries at least min's authority.
func (r Role) meets(min Role) bool {
	return roleRank[r] >= roleRank[min]
}

// RoleMapping is a customer's claim-value -> Role assignment: the "existing
// group names work without a table" half of N2. Built once by
// newRoleMapping from startup configuration and never modified afterward.
type RoleMapping map[string]Role

// newRoleMapping builds a RoleMapping from three configured group lists, one
// per role, and rejects a claim value listed under more than one: silently
// letting the later list win would make an operator's actual access depend
// on argument order rather than anything they configured -- the same
// fail-fast treatment internal/config's splitPolicyLanguages gives a stray
// comma, applied here to an ambiguity that would otherwise surface only as
// "why does this operator have editor access."
func newRoleMapping(adminGroups, editorGroups, viewerGroups []string) (RoleMapping, error) {
	m := make(RoleMapping)
	assign := func(groups []string, role Role) error {
		for _, g := range groups {
			if existing, ok := m[g]; ok {
				return fmt.Errorf("group %q is mapped to both %s and %s", g, existing, role)
			}
			m[g] = role
		}
		return nil
	}
	if err := assign(adminGroups, RoleAdmin); err != nil {
		return nil, err
	}
	if err := assign(editorGroups, RoleEditor); err != nil {
		return nil, err
	}
	if err := assign(viewerGroups, RoleViewer); err != nil {
		return nil, err
	}
	return m, nil
}

// errRoleClaimAbsent and errRoleClaimUnrecognized are distinct so callers
// (and tests) can tell "this token carries no role claim at all" apart from
// "it carries one naming a group nobody configured" via errors.Is, without
// parsing message text. Both are refusals; N2 draws no distinction between
// them in what happens next (the request is denied either way) but the
// distinction matters for diagnosing a misconfiguration versus an
// unprovisioned operator.
var (
	errRoleClaimAbsent       = errors.New("role claim absent")
	errRoleClaimUnrecognized = errors.New("role claim value not recognized")
)

// resolveRole reads claimName out of a verified token's claims and maps it
// to a Role via mapping. It returns a non-empty Role only alongside a nil
// error -- every failure path returns ("", err), never a guessed role. N2 is
// explicit that an absent or unrecognised claim is a refusal, not a default:
// this function has no branch that returns RoleViewer (or any role) without
// mapping having actually named one.
//
// The claim value may be a single string or a JSON array of strings. Real
// IdPs (Okta, Azure AD, Auth0) issue group membership as an array far more
// often than a single scalar role name, and N2's "so a customer's existing
// group names work" only holds up if an operator belonging to more than one
// group is handled at all. Among an array's matches, the highest-ranked
// role wins: an operator in both "all-staff" (mapped to viewer) and
// "stratium-admins" (mapped to admin) is an admin, not silently shadowed by
// the broader group. A non-string array entry is skipped rather than
// treated as a failure -- it names no configured group either way, the same
// outcome as a string entry that simply does not match.
func resolveRole(claims map[string]any, claimName string, mapping RoleMapping) (Role, error) {
	raw, ok := claims[claimName]
	if !ok {
		return "", errRoleClaimAbsent
	}

	switch v := raw.(type) {
	case string:
		role, ok := mapping[v]
		if !ok {
			return "", errRoleClaimUnrecognized
		}
		return role, nil
	case []any:
		best := Role("")
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				continue
			}
			if role, ok := mapping[s]; ok && roleRank[role] > roleRank[best] {
				best = role
			}
		}
		if best == "" {
			return "", errRoleClaimUnrecognized
		}
		return best, nil
	default:
		// Neither a string nor an array of strings -- e.g. a number or an
		// object, a shape no real IdP uses for group membership. Refusing
		// this is the same "unrecognised" outcome as a string claim naming
		// an unconfigured group, not a distinct error: both mean "this
		// claim, as presented, names no role mapping recognizes."
		return "", errRoleClaimUnrecognized
	}
}
