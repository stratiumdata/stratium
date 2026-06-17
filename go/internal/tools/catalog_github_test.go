package tools

import (
	"testing"

	ag "stratium/services/agent-gateway"

	"github.com/stretchr/testify/assert"
)

func TestExtractReason(t *testing.T) {
	t.Run("prefers delegation reason and appends denied principal", func(t *testing.T) {
		resp := &ag.ExecuteActionResponse{
			Authorized: false,
			Decision: &ag.CompoundDecision{
				DelegationReason: "tier exceeds cap",
				DeniedPrincipal:  "delegation",
			},
		}
		assert.Equal(t, "tier exceeds cap (denied by delegation)", extractReason(resp))
	})

	t.Run("falls back to error field", func(t *testing.T) {
		resp := &ag.ExecuteActionResponse{Authorized: false, Error: "boom"}
		assert.Equal(t, "boom", extractReason(resp))
	})

	t.Run("selects AgentReason when DelegationReason is empty", func(t *testing.T) {
		resp := &ag.ExecuteActionResponse{
			Authorized: false,
			Decision: &ag.CompoundDecision{
				AgentReason: "agent policy denied",
			},
		}
		assert.Equal(t, "agent policy denied", extractReason(resp))
	})

	t.Run("selects UserReason when DelegationReason and AgentReason are empty", func(t *testing.T) {
		resp := &ag.ExecuteActionResponse{
			Authorized: false,
			Decision: &ag.CompoundDecision{
				UserReason: "user lacks clearance",
			},
		}
		assert.Equal(t, "user lacks clearance", extractReason(resp))
	})

	t.Run("appends DeniedPrincipal to reason", func(t *testing.T) {
		resp := &ag.ExecuteActionResponse{
			Authorized: false,
			Decision: &ag.CompoundDecision{
				DelegationReason: "x",
				DeniedPrincipal:  "agent",
			},
		}
		assert.Equal(t, "x (denied by agent)", extractReason(resp))
	})

	t.Run("nil Decision with Error field", func(t *testing.T) {
		resp := &ag.ExecuteActionResponse{Authorized: false, Error: "boom"}
		assert.Equal(t, "boom", extractReason(resp))
	})

	t.Run("both Decision.DelegationReason and resp.Error set: Error wins", func(t *testing.T) {
		// documents current parity with actions.go: resp.Error wins when both are set
		resp := &ag.ExecuteActionResponse{
			Authorized: false,
			Decision: &ag.CompoundDecision{
				DelegationReason: "cap exceeded",
			},
			Error: "rpc fail",
		}
		assert.Equal(t, "rpc fail", extractReason(resp))
	})
}
