# Phase 1b — chain integrity and C24 reclassification

Two follow-ups from the final whole-branch review. Both close gaps that are
latent in Phase 1 and become expensive once Phase 2 has callers.

## Task A — `ValidateChain`

`Decide` trusts whatever slice it is handed. A chain mixing tenants, with a
fabricated `Depth` and an orphan `ParentDelegationID`, returns ALLOW. Nothing
reaches it today because no caller exists; Phase 2 adds three producers (PDP
reading from the database, cache rehydration, token-claim derivation) and only
the first gets tenant safety from RLS.

`audit.Verify` already set the precedent — it enforces tenant consistency
rather than documenting it as a precondition, on the grounds that the
auditor-facing proof should not depend on a caller's diligence. `Decide` is
the authorization-facing proof.

**New file `services/internal/authz/chain.go`:**

```go
package authz

import (
	"errors"
	"fmt"

	"github.com/google/uuid"

	"stratium/pkg/models"
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
		prev := chain[i-1]
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
```

**Wire it into `Decide`**, immediately after the declared-tier cross-check and
before any leg is evaluated. An invalid chain is attributed to the delegation
leg and denies:

```go
	if err := ValidateChain(req.Chain, req.TenantID, req.Agent.ID); err != nil {
		res.Effect = EffectDeny
		res.DeniedLeg = "delegation"
		res.Reason = err.Error()
		res.Delegation = LegResult{Effect: EffectDeny, Reason: err.Error()}
		return res
	}
```

**Tests** must cover each rejection individually — a table where one field is
corrupted per case, so no single check can be removed without a named failure:
empty, nil at index 0, nil mid-chain, non-root first element, root with depth
≠ 0, a tenant mismatch anywhere, a wrong `RootDelegationID`, a missing parent
pointer, a parent pointing at the wrong delegation, a depth that skips, and an
acting delegation issued to a different agent. Plus a valid three-hop chain
that passes, and a valid single-hop root.

## Task B — reclassify C24

C24's property is "an expired delegation **token** is denied even if a cache
entry exists." Tokens and caches are Phase 3. The current test checks
delegation expiry, which `TestDelegationLeg_DeniesExpiredHop` already covers,
so C24 reports a guarantee nothing establishes.

Replace the body with a skip naming Phase 3, keeping `markRan(24)` first so
the gate's count stays 25:

```go
func TestC24_ExpiredDelegationDenied(t *testing.T) {
	markRan(24)
	t.Skip("Phase 3: the property is about an expired TOKEN with a live cache " +
		"entry; neither exists yet. Delegation expiry alone is covered by " +
		"TestDelegationLeg_DeniesExpiredHop.")
}
```

Suite becomes 13 pass / 12 skip / 25 accounted for.
