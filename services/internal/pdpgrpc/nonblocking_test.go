package pdpgrpc

import "testing"

// TestDegradeEscalateToDeny proves the mapping a non-blocking surface would
// perform directly, on the wire response type, without needing the extauthz
// surface itself to exist (see nonblocking.go's own doc comment, and
// TestC23_NonBlockingSurfaceDegradesToDeny in internal/authz/conformance_test.go
// for what still does). Table-driven over every reachable Effect plus the
// defensive nil case, rather than one test per case: the property under test
// is a single small function with four inputs, and a shared assertion shape
// keeps each case's intent legible without four near-duplicate test bodies.
func TestDegradeEscalateToDeny(t *testing.T) {
	tests := []struct {
		name         string
		resp         *DecideResponse
		wantDeny     bool
		wantApproval string
	}{
		{
			name:         "escalate degrades to deny, approval id carried forward",
			resp:         &DecideResponse{Effect: Effect_EFFECT_ESCALATE, ApprovalId: "11111111-1111-1111-1111-111111111111"},
			wantDeny:     true,
			wantApproval: "11111111-1111-1111-1111-111111111111",
		},
		{
			name:         "a genuine deny stays deny, and fabricates no approval id",
			resp:         &DecideResponse{Effect: Effect_EFFECT_DENY, DeniedLeg: "principal"},
			wantDeny:     true,
			wantApproval: "",
		},
		{
			name:         "allow passes through as not-deny",
			resp:         &DecideResponse{Effect: Effect_EFFECT_ALLOW},
			wantDeny:     false,
			wantApproval: "",
		},
		{
			name:         "a nil response fails closed to deny, not allow",
			resp:         nil,
			wantDeny:     true,
			wantApproval: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deny, approvalID := DegradeEscalateToDeny(tt.resp)
			if deny != tt.wantDeny {
				t.Errorf("deny = %v, want %v", deny, tt.wantDeny)
			}
			if approvalID != tt.wantApproval {
				t.Errorf("approvalID = %q, want %q", approvalID, tt.wantApproval)
			}
		})
	}
}
