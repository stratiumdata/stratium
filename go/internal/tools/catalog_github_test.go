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
}
