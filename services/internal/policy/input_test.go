package policy

import (
	"testing"

	"github.com/google/uuid"

	"stratium/internal/authz"
	"stratium/pkg/models"
)

// TestEvaluationInput_CarriesEveryDimension guards the fix for spec defect
// D6: the predecessor's EvaluationInput was Subject/Resource/Action/
// Environment with no agent or delegation dimension, which is the structural
// reason the agent authorization path could never call a policy engine.
// Every dimension the type's doc comment promises must actually survive
// assignment — a field silently dropped here would reopen D6 one layer down.
func TestEvaluationInput_CarriesEveryDimension(t *testing.T) {
	agentID := uuid.New()
	in := EvaluationInput{
		Principal:   authz.Principal{Subject: "alice@example.com", Attributes: map[string]string{"dept": "eng"}},
		Action:      authz.Action{Tool: "Bash", Verb: "read"},
		DerivedTier: models.ActionTierReadOnly,
		Resource:    map[string]string{"path": "/tmp/x"},
		Environment: map[string]string{"ip": "10.0.0.1"},
		Agent:       authz.AgentInfo{ID: agentID, TrustTier: models.TrustTierCertified},
		Delegation: DelegationContext{
			Depth:              2,
			MaxActionTier:      models.ActionTierInternalModify,
			ClassificationCaps: map[string]string{"pii": "none"},
			Purpose:            "quarterly report",
		},
	}

	if got := in.Principal.Subject; got != "alice@example.com" {
		t.Errorf("Principal not carried: got %q", got)
	}
	if got := in.Action.Tool; got != "Bash" {
		t.Errorf("Action not carried: got %q", got)
	}
	if got := in.DerivedTier; got != models.ActionTierReadOnly {
		t.Errorf("DerivedTier not carried: got %v", got)
	}
	if got := in.Resource["path"]; got != "/tmp/x" {
		t.Errorf("Resource not carried: got %v", in.Resource)
	}
	if got := in.Environment["ip"]; got != "10.0.0.1" {
		t.Errorf("Environment not carried: got %v", in.Environment)
	}
	if got := in.Agent.ID; got != agentID {
		t.Errorf("Agent not carried: got %v", got)
	}
	want := DelegationContext{
		Depth:              2,
		MaxActionTier:      models.ActionTierInternalModify,
		ClassificationCaps: map[string]string{"pii": "none"},
		Purpose:            "quarterly report",
	}
	if in.Delegation.Depth != want.Depth ||
		in.Delegation.MaxActionTier != want.MaxActionTier ||
		in.Delegation.Purpose != want.Purpose ||
		in.Delegation.ClassificationCaps["pii"] != want.ClassificationCaps["pii"] {
		t.Errorf("Delegation not carried: got %+v, want %+v", in.Delegation, want)
	}
}
