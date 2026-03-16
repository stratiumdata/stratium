package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestCreateAuditLogRequest_ToAuditLog verifies all fields are populated.
func TestCreateAuditLogRequest_ToAuditLog(t *testing.T) {
	entityID := uuid.New()
	req := &CreateAuditLogRequest{
		EntityType: EntityTypePolicy,
		EntityID:   &entityID,
		Action:     AuditActionCreate,
		Actor:      "alice",
		Changes:    map[string]interface{}{"name": "new-policy"},
		Result:     map[string]interface{}{"success": true},
		IPAddress:  "10.0.0.1",
		UserAgent:  "test-agent/1.0",
	}

	before := time.Now()
	log := req.ToAuditLog()
	after := time.Now()

	if log.ID == (uuid.UUID{}) {
		t.Error("ToAuditLog() ID should not be zero UUID")
	}
	if log.EntityType != EntityTypePolicy {
		t.Errorf("EntityType = %q, want %q", log.EntityType, EntityTypePolicy)
	}
	if log.EntityID == nil || *log.EntityID != entityID {
		t.Errorf("EntityID = %v, want %v", log.EntityID, entityID)
	}
	if log.Action != AuditActionCreate {
		t.Errorf("Action = %q, want %q", log.Action, AuditActionCreate)
	}
	if log.Actor != "alice" {
		t.Errorf("Actor = %q, want 'alice'", log.Actor)
	}
	if log.IPAddress != "10.0.0.1" {
		t.Errorf("IPAddress = %q, want '10.0.0.1'", log.IPAddress)
	}
	if log.Timestamp.Before(before) || log.Timestamp.After(after) {
		t.Errorf("Timestamp = %v, expected between %v and %v", log.Timestamp, before, after)
	}
}

// TestCreateAuditLogRequest_ToAuditLog_NilEntityID verifies nil EntityID is preserved.
func TestCreateAuditLogRequest_ToAuditLog_NilEntityID(t *testing.T) {
	req := &CreateAuditLogRequest{
		EntityType: EntityTypeEntitlement,
		Action:     AuditActionEvaluate,
		Actor:      "system",
	}

	log := req.ToAuditLog()
	if log.EntityID != nil {
		t.Errorf("EntityID = %v, want nil", log.EntityID)
	}
}

// TestAuditLog_MarshalJSON verifies UUID and EntityID are serialized as strings.
func TestAuditLog_MarshalJSON(t *testing.T) {
	entityID := uuid.New()
	a := &AuditLog{
		ID:         uuid.New(),
		EntityType: EntityTypePolicy,
		EntityID:   &entityID,
		Action:     AuditActionUpdate,
		Actor:      "bob",
		Timestamp:  time.Now(),
		IPAddress:  "192.168.1.1",
	}

	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}

	if id, ok := out["id"].(string); !ok || id == "" {
		t.Error("MarshalJSON() id should be non-empty string")
	}
	if eid, ok := out["entity_id"].(string); !ok || eid == "" {
		t.Error("MarshalJSON() entity_id should be non-empty string")
	}
}

// TestAuditLog_MarshalJSON_NilEntityID verifies entity_id is omitted when nil.
func TestAuditLog_MarshalJSON_NilEntityID(t *testing.T) {
	a := &AuditLog{
		ID:        uuid.New(),
		Action:    AuditActionDelete,
		Actor:     "admin",
		Timestamp: time.Now(),
	}

	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}

	if _, exists := out["entity_id"]; exists {
		t.Error("MarshalJSON() entity_id should be omitted when nil")
	}
}

// TestUUIDPtrToStringPtr_Nil verifies nil input returns nil.
func TestUUIDPtrToStringPtr_Nil(t *testing.T) {
	if uuidPtrToStringPtr(nil) != nil {
		t.Error("uuidPtrToStringPtr(nil) should return nil")
	}
}

// TestUUIDPtrToStringPtr_NonNil verifies non-nil UUID is converted to string.
func TestUUIDPtrToStringPtr_NonNil(t *testing.T) {
	id := uuid.New()
	s := uuidPtrToStringPtr(&id)
	if s == nil {
		t.Fatal("uuidPtrToStringPtr() returned nil for non-nil UUID")
	}
	if *s != id.String() {
		t.Errorf("uuidPtrToStringPtr() = %q, want %q", *s, id.String())
	}
}

// TestAuditConstants verifies all constants are non-empty.
func TestAuditConstants(t *testing.T) {
	entityTypes := []EntityType{EntityTypePolicy, EntityTypeEntitlement}
	for _, et := range entityTypes {
		if et == "" {
			t.Errorf("EntityType constant is empty")
		}
	}

	actions := []AuditAction{
		AuditActionCreate, AuditActionUpdate, AuditActionDelete,
		AuditActionEvaluate, AuditActionTest,
	}
	for _, a := range actions {
		if a == "" {
			t.Errorf("AuditAction constant is empty")
		}
	}
}
