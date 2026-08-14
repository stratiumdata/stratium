package main

import (
	"errors"
	"strings"
	"testing"
)

// TestRole_Meets defends the ranking every role-gated route relies on:
// admin outranks editor outranks viewer, and critically, the zero Role
// ("", what a variable holds before resolveRole ever succeeds) meets
// nothing -- not even the lowest real role. If it met RoleViewer, a bug
// that left an Operator's Role unset would read as a valid viewer instead
// of failing every authorize check, which is exactly the fail-open shape
// N2 forbids.
func TestRole_Meets(t *testing.T) {
	tests := []struct {
		name string
		have Role
		min  Role
		want bool
	}{
		{"viewer meets viewer", RoleViewer, RoleViewer, true},
		{"viewer does not meet editor", RoleViewer, RoleEditor, false},
		{"viewer does not meet admin", RoleViewer, RoleAdmin, false},
		{"editor meets viewer", RoleEditor, RoleViewer, true},
		{"editor meets editor", RoleEditor, RoleEditor, true},
		{"editor does not meet admin", RoleEditor, RoleAdmin, false},
		{"admin meets viewer", RoleAdmin, RoleViewer, true},
		{"admin meets editor", RoleAdmin, RoleEditor, true},
		{"admin meets admin", RoleAdmin, RoleAdmin, true},
		{"zero value meets nothing, not even viewer", Role(""), RoleViewer, false},
		{"unrecognised role value meets nothing", Role("superuser"), RoleViewer, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.have.meets(tt.min); got != tt.want {
				t.Errorf("%s.meets(%s) = %v, want %v", tt.have, tt.min, got, tt.want)
			}
		})
	}
}

// TestNewRoleMapping_BuildsClaimValueToRole confirms each configured group
// name lands on the role its own list named -- the "customer's existing
// group names work without a table" property N2 asks for, checked directly
// against the map newRoleMapping produces rather than only indirectly
// through resolveRole.
func TestNewRoleMapping_BuildsClaimValueToRole(t *testing.T) {
	m, err := newRoleMapping(
		[]string{"org-admins"},
		[]string{"org-editors", "org-writers"},
		[]string{"org-everyone"},
	)
	if err != nil {
		t.Fatalf("newRoleMapping() error = %v, want nil", err)
	}
	want := RoleMapping{
		"org-admins":   RoleAdmin,
		"org-editors":  RoleEditor,
		"org-writers":  RoleEditor,
		"org-everyone": RoleViewer,
	}
	if len(m) != len(want) {
		t.Fatalf("newRoleMapping() = %v, want %v", m, want)
	}
	for group, role := range want {
		if m[group] != role {
			t.Errorf("mapping[%q] = %q, want %q", group, m[group], role)
		}
	}
}

// TestNewRoleMapping_DuplicateGroupAcrossRoles_Errors is the fail-fast
// counterpart: a group name configured under two roles is ambiguous, and
// resolving that silently by whichever list happened to be applied last
// would make an operator's real access depend on newRoleMapping's own
// argument order rather than anything they configured. Caught here, at
// startup, rather than surfacing as "why does this operator have editor
// access, the config only lists them as a viewer."
func TestNewRoleMapping_DuplicateGroupAcrossRoles_Errors(t *testing.T) {
	_, err := newRoleMapping(
		[]string{"org-staff"},
		[]string{"org-staff"},
		nil,
	)
	if err == nil {
		t.Fatal("newRoleMapping() error = nil, want an error naming the duplicated group")
	}
	if !containsAll(err.Error(), "org-staff", "admin", "editor") {
		t.Errorf("error = %q, want it to name the duplicated group and both conflicting roles", err.Error())
	}
}

// TestResolveRole_AbsentClaim_Refuses is the direct anchor for the required
// mutation "treat an absent role claim as viewer" (task brief, N2): claims
// with nothing under claimName at all must return errRoleClaimAbsent and
// the zero Role -- never RoleViewer, never any role.
func TestResolveRole_AbsentClaim_Refuses(t *testing.T) {
	mapping := RoleMapping{"org-admins": RoleAdmin}
	claims := map[string]any{"sub": "operator-1"} // no "roles" key at all

	role, err := resolveRole(claims, "roles", mapping)

	if !errors.Is(err, errRoleClaimAbsent) {
		t.Errorf("err = %v, want errRoleClaimAbsent", err)
	}
	if role == RoleViewer {
		t.Error("resolveRole defaulted an absent claim to RoleViewer -- N2 requires refusal, never a default role")
	}
	if role != "" {
		t.Errorf("role = %q, want the zero value on refusal", role)
	}
}

func TestResolveRole(t *testing.T) {
	mapping, err := newRoleMapping(
		[]string{"org-admins"},
		[]string{"org-editors"},
		[]string{"org-everyone"},
	)
	if err != nil {
		t.Fatalf("newRoleMapping() error = %v", err)
	}

	tests := []struct {
		name      string
		claims    map[string]any
		wantRole  Role
		wantErr   error
		wantIsErr bool
	}{
		{
			name:     "single string claim value maps to its configured role",
			claims:   map[string]any{"roles": "org-admins"},
			wantRole: RoleAdmin,
		},
		{
			name:      "unrecognised string claim value refuses",
			claims:    map[string]any{"roles": "org-unknown-group"},
			wantErr:   errRoleClaimUnrecognized,
			wantIsErr: true,
		},
		{
			name:     "array claim picks the matching entry",
			claims:   map[string]any{"roles": []any{"org-editors"}},
			wantRole: RoleEditor,
		},
		{
			name: "array claim with multiple matches picks the highest-ranked role",
			claims: map[string]any{
				"roles": []any{"org-everyone", "org-admins"},
			},
			wantRole: RoleAdmin,
		},
		{
			name:      "array claim with no matching entries refuses",
			claims:    map[string]any{"roles": []any{"org-unknown-a", "org-unknown-b"}},
			wantErr:   errRoleClaimUnrecognized,
			wantIsErr: true,
		},
		{
			name:     "array claim ignores non-string entries but still resolves the rest",
			claims:   map[string]any{"roles": []any{42, "org-editors"}},
			wantRole: RoleEditor,
		},
		{
			name:      "claim present but the wrong JSON type refuses rather than panicking",
			claims:    map[string]any{"roles": float64(1)},
			wantErr:   errRoleClaimUnrecognized,
			wantIsErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role, err := resolveRole(tt.claims, "roles", mapping)
			if tt.wantIsErr {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("err = %v, want %v", err, tt.wantErr)
				}
				if role != "" {
					t.Errorf("role = %q, want the zero value alongside a refusal", role)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveRole() error = %v, want nil", err)
			}
			if role != tt.wantRole {
				t.Errorf("role = %q, want %q", role, tt.wantRole)
			}
		})
	}
}

// containsAll reports whether s contains every substring in subs -- a small
// local helper so the tests above can assert an error names several things
// without a brittle exact-string match on wording that may still change.
func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
