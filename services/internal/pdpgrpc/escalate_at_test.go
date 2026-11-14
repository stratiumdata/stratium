package pdpgrpc

import (
	"testing"

	"github.com/stratiumdata/stratium/internal/authz"
	"github.com/stratiumdata/stratium/pkg/models"
)

// One row per case in the plan's "Effective threshold" table, plus the two
// properties that matter most: a caller can neither raise nor remove an
// inherited threshold.
func TestEffectiveEscalateAt(t *testing.T) {
	const (
		read     = models.ActionTierReadOnly
		internal = models.ActionTierInternalModify
		external = models.ActionTierExternalComms
		destruct = models.ActionTierDestructive
	)
	for _, tc := range []struct {
		name               string
		inherited, request *models.ActionTier
		grantedMax         models.ActionTier
		want               *models.ActionTier
		wantRemoved        bool
	}{
		{"nothing anywhere: never escalates", nil, nil, destruct, nil, false},
		{"inherited only", tierPtr(destruct), nil, destruct, tierPtr(destruct), false},
		{"request lowers the inherited threshold", tierPtr(destruct), tierPtr(external), destruct, tierPtr(external), false},
		{"request cannot RAISE the inherited threshold", tierPtr(internal), tierPtr(destruct), destruct, tierPtr(internal), false},
		{"omitting a request cannot REMOVE the inherited threshold", tierPtr(internal), nil, destruct, tierPtr(internal), false},
		{"request alone, nothing inherited", nil, tierPtr(external), destruct, tierPtr(external), false},
		{"threshold above the granted ceiling is dropped", tierPtr(destruct), nil, external, nil, true},
		{"threshold AT the granted ceiling is kept", tierPtr(external), nil, external, tierPtr(external), false},
		{"lowered below a clamped ceiling is kept", tierPtr(destruct), tierPtr(read), external, tierPtr(read), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, removed := effectiveEscalateAt(tc.inherited, tc.request, tc.grantedMax)
			switch {
			case tc.want == nil && got != nil:
				t.Errorf("got %s, want none", *got)
			case tc.want != nil && (got == nil || *got != *tc.want):
				t.Errorf("got %v, want %s", got, *tc.want)
			}
			if (removed != nil) != tc.wantRemoved {
				t.Fatalf("removed = %+v, want removed=%v", removed, tc.wantRemoved)
			}
			if removed != nil && (removed.Dimension != "escalate_at" || removed.Reason != authz.ClampReasonUnreachable) {
				t.Errorf("removal = %+v, want an unreachable escalate_at removal", removed)
			}
		})
	}
}

// The function must not alias the caller's request pointer into the result:
// the delegation would otherwise share memory with a request-scoped value.
func TestEffectiveEscalateAt_DoesNotAliasTheRequest(t *testing.T) {
	req := tierPtr(models.ActionTierReadOnly)
	got, _ := effectiveEscalateAt(nil, req, models.ActionTierDestructive)
	if got == req {
		t.Error("result aliases the request pointer")
	}
}
