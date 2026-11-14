package authz

import (
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/pkg/models"
)

// ErrChainInvalid indicates the delegation chain is not a well-formed lineage.
// It is distinct from a denial: a denial means the chain is valid and does not
// authorize the action; this means the chain itself cannot be trusted to mean
// anything.
var ErrChainInvalid = errors.New("delegation chain is not well-formed")

// ValidateChain checks that a chain is a genuine lineage before any decision is
// computed from it.
//
// Enforced rather than documented, for the same reason audit.Verify enforces
// its tenant precondition: three separate Phase 2 paths will assemble chains —
// database reads, cache rehydration, and token-claim derivation — and only the
// first is covered by row-level security. A precondition that lives in a doc
// comment is a precondition the third caller will not know about.
//
// Chain must be ordered root-first with the acting delegation last.
func ValidateChain(chain []*models.Delegation, tenantID string, actingAgent uuid.UUID) error {
	if len(chain) == 0 {
		return fmt.Errorf("%w: empty", ErrChainInvalid)
	}

	root := chain[0]
	if root == nil {
		return fmt.Errorf("%w: nil delegation at depth 0", ErrChainInvalid)
	}
	if !root.IsRoot() {
		return fmt.Errorf("%w: first delegation %s has a parent, so it is not a root",
			ErrChainInvalid, root.ID)
	}
	if root.Depth != 0 {
		return fmt.Errorf("%w: root %s claims depth %d", ErrChainInvalid, root.ID, root.Depth)
	}

	for i, d := range chain {
		if d == nil {
			return fmt.Errorf("%w: nil delegation at index %d", ErrChainInvalid, i)
		}
		if d.TenantID != tenantID {
			return fmt.Errorf("%w: delegation %s belongs to tenant %q, request is for %q",
				ErrChainInvalid, d.ID, d.TenantID, tenantID)
		}
		if d.RootDelegationID != root.ID {
			return fmt.Errorf("%w: delegation %s claims root %s, chain root is %s",
				ErrChainInvalid, d.ID, d.RootDelegationID, root.ID)
		}
		if i == 0 {
			continue
		}
		prev := chain[i-1] //nolint:gosec // G602: i==0 continues above, so i-1 is always in range here
		if d.ParentDelegationID == nil {
			return fmt.Errorf("%w: delegation %s at index %d has no parent", ErrChainInvalid, d.ID, i)
		}
		if *d.ParentDelegationID != prev.ID {
			return fmt.Errorf("%w: delegation %s claims parent %s, predecessor is %s",
				ErrChainInvalid, d.ID, *d.ParentDelegationID, prev.ID)
		}
		if d.Depth != prev.Depth+1 {
			return fmt.Errorf("%w: delegation %s claims depth %d, predecessor is at %d",
				ErrChainInvalid, d.ID, d.Depth, prev.Depth)
		}
	}

	// The acting delegation is the last hop; the agent presenting it must be
	// the agent it was issued to. Without this an agent can act under another
	// agent's delegation.
	if acting := chain[len(chain)-1]; acting.AgentID != actingAgent {
		return fmt.Errorf("%w: acting delegation %s was issued to agent %s, not %s",
			ErrChainInvalid, acting.ID, acting.AgentID, actingAgent)
	}

	return nil
}
