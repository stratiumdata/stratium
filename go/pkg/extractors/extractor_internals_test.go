package extractors

import (
	"testing"

	"stratium/pkg/auth"
)

// TestConvertMapToStringMap_Basic verifies values are copied to a new map.
func TestConvertMapToStringMap_Basic(t *testing.T) {
	input := map[string]interface{}{
		"role":  "admin",
		"count": 42,
	}
	result := convertMapToStringMap(input)

	if len(result) != len(input) {
		t.Errorf("len = %d, want %d", len(result), len(input))
	}
	if result["role"] != "admin" {
		t.Errorf("role = %v, want 'admin'", result["role"])
	}
}

// TestConvertMapToStringMap_Empty verifies empty map returns empty result.
func TestConvertMapToStringMap_Empty(t *testing.T) {
	result := convertMapToStringMap(map[string]interface{}{})
	if len(result) != 0 {
		t.Errorf("len = %d, want 0", len(result))
	}
}

// TestConvertMapToStringMap_Independence verifies modifying result doesn't affect input.
func TestConvertMapToStringMap_Independence(t *testing.T) {
	input := map[string]interface{}{"key": "value"}
	result := convertMapToStringMap(input)
	result["key"] = "modified"
	if input["key"] != "value" {
		t.Error("convertMapToStringMap() result shares storage with input")
	}
}

// TestUserClaimsToAttributes_BasicFields verifies standard claim fields are mapped.
func TestUserClaimsToAttributes_BasicFields(t *testing.T) {
	claims := &auth.UserClaims{
		Sub:               "user-123",
		Email:             "user@example.com",
		PreferredUsername: "jdoe",
		Name:              "John Doe",
		GivenName:         "John",
		FamilyName:        "Doe",
		Scope:             "openid profile",
		Classification:    "unclassified",
		ClientID:          "my-client",
		AuthorizedParty:   "my-client",
	}

	attrs := userClaimsToAttributes(claims)

	for field, want := range map[string]string{
		"sub":                "user-123",
		"email":              "user@example.com",
		"preferred_username": "jdoe",
		"name":               "John Doe",
		"given_name":         "John",
		"family_name":        "Doe",
		"scope":              "openid profile",
		"classification":     "unclassified",
		"client_id":          "my-client",
		"azp":                "my-client",
	} {
		got, ok := attrs[field].(string)
		if !ok {
			t.Errorf("attr[%q] type = %T, want string", field, attrs[field])
			continue
		}
		if got != want {
			t.Errorf("attr[%q] = %q, want %q", field, got, want)
		}
	}
}

// TestUserClaimsToAttributes_Roles verifies roles are included when non-empty.
func TestUserClaimsToAttributes_Roles(t *testing.T) {
	claims := &auth.UserClaims{
		Roles: []string{"admin", "reader"},
	}

	attrs := userClaimsToAttributes(claims)

	roles, ok := attrs["roles"].([]string)
	if !ok {
		t.Fatalf("roles type = %T, want []string", attrs["roles"])
	}
	if len(roles) != 2 || roles[0] != "admin" {
		t.Errorf("roles = %v, want [admin reader]", roles)
	}
}

// TestUserClaimsToAttributes_EmptyRoles verifies roles key is absent for empty slice.
func TestUserClaimsToAttributes_EmptyRoles(t *testing.T) {
	claims := &auth.UserClaims{
		Roles:  []string{},
		Groups: []string{},
	}

	attrs := userClaimsToAttributes(claims)

	if _, ok := attrs["roles"]; ok {
		t.Error("roles should not be present when empty")
	}
	if _, ok := attrs["groups"]; ok {
		t.Error("groups should not be present when empty")
	}
}

// TestUserClaimsToAttributes_Groups verifies groups are included when non-empty.
func TestUserClaimsToAttributes_Groups(t *testing.T) {
	claims := &auth.UserClaims{
		Groups: []string{"engineering", "platform"},
	}

	attrs := userClaimsToAttributes(claims)

	groups, ok := attrs["groups"].([]string)
	if !ok {
		t.Fatalf("groups type = %T, want []string", attrs["groups"])
	}
	if len(groups) != 2 || groups[0] != "engineering" {
		t.Errorf("groups = %v, want [engineering platform]", groups)
	}
}
