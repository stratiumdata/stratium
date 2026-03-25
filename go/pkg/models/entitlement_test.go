package models

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newValidEntitlement() *Entitlement {
	return &Entitlement{
		ID:                uuid.New(),
		Name:              "test-entitlement",
		SubjectAttributes: map[string]interface{}{"role": "admin"},
		Actions:           []string{"read", "write"},
		Enabled:           true,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}
}

func TestCreateEntitlementRequest_ToEntitlement(t *testing.T) {
	expiry := time.Now().Add(24 * time.Hour)
	req := &CreateEntitlementRequest{
		Name:               "my-entitlement",
		Description:        "desc",
		SubjectAttributes:  map[string]interface{}{"role": "reader"},
		ResourceAttributes: map[string]interface{}{"type": "document"},
		Actions:            []string{"read"},
		Conditions:         map[string]interface{}{"env": "prod"},
		Enabled:            true,
		ExpiresAt:          &expiry,
	}

	ent := req.ToEntitlement("alice")
	if ent.ID == (uuid.UUID{}) {
		t.Error("ToEntitlement() ID should not be zero")
	}
	if ent.Name != req.Name {
		t.Errorf("Name = %q, want %q", ent.Name, req.Name)
	}
	if !ent.CreatedBy.Valid || ent.CreatedBy.String != "alice" {
		t.Errorf("CreatedBy = %v, want 'alice'", ent.CreatedBy)
	}
	if ent.ExpiresAt == nil || !ent.ExpiresAt.Equal(expiry) {
		t.Error("ExpiresAt not propagated correctly")
	}

	// Anonymous creator
	ent2 := req.ToEntitlement("")
	if ent2.CreatedBy.Valid {
		t.Error("CreatedBy should be invalid for empty creator")
	}
}

func TestEntitlement_ApplyUpdate(t *testing.T) {
	e := newValidEntitlement()
	newName := "updated-name"
	newEnabled := false
	newActions := []string{"delete"}
	newSubject := map[string]interface{}{"role": "viewer"}

	req := &UpdateEntitlementRequest{
		Name:              &newName,
		Enabled:           &newEnabled,
		Actions:           &newActions,
		SubjectAttributes: &newSubject,
	}

	before := e.UpdatedAt
	time.Sleep(time.Millisecond) // ensure UpdatedAt changes
	e.ApplyUpdate(req, "bob")

	if e.Name != newName {
		t.Errorf("Name = %q, want %q", e.Name, newName)
	}
	if e.Enabled != newEnabled {
		t.Errorf("Enabled = %v, want %v", e.Enabled, newEnabled)
	}
	if len(e.Actions) != 1 || e.Actions[0] != "delete" {
		t.Errorf("Actions = %v, want [delete]", e.Actions)
	}
	if e.UpdatedBy.String != "bob" {
		t.Errorf("UpdatedBy = %q, want 'bob'", e.UpdatedBy.String)
	}
	if !e.UpdatedAt.After(before) {
		t.Error("UpdatedAt should be after the pre-update timestamp")
	}
}

func TestEntitlement_ApplyUpdate_NilFields(t *testing.T) {
	e := newValidEntitlement()
	origName := e.Name

	// All nil fields — nothing should change except UpdatedBy/UpdatedAt
	e.ApplyUpdate(&UpdateEntitlementRequest{}, "system")

	if e.Name != origName {
		t.Errorf("Name changed unexpectedly: got %q, want %q", e.Name, origName)
	}
}

func TestEntitlement_MarshalJSON(t *testing.T) {
	e := newValidEntitlement()
	e.CreatedBy = sql.NullString{String: "alice", Valid: true}
	e.UpdatedBy = sql.NullString{String: "", Valid: false}

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("Unmarshal after MarshalJSON error = %v", err)
	}

	if id, ok := out["id"].(string); !ok || id == "" {
		t.Error("MarshalJSON() should serialize ID as non-empty string")
	}
	if createdBy, ok := out["created_by"].(string); !ok || createdBy != "alice" {
		t.Errorf("MarshalJSON() created_by = %v, want 'alice'", out["created_by"])
	}
	if updatedBy, ok := out["updated_by"].(string); !ok || updatedBy != "" {
		t.Errorf("MarshalJSON() updated_by = %v, want ''", out["updated_by"])
	}
}
