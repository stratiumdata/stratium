package authz

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"stratium/pkg/models"
)

// chainTenant is the well-formed baseline tenant every rejection test below
// corrupts exactly one field away from. Keeping it fixed makes each test's
// diff from "valid" the only thing worth reading.
const chainTenant = "tenant-a"

// requireChainError fails the test unless err wraps ErrChainInvalid and its
// message contains want — the substring identifying which check inside
// ValidateChain produced it. Each case below corrupts exactly one field of an
// otherwise well-formed chain, so only one check can be the source; the
// substring pins that check so removing it (not some other check) is what
// makes the test fail.
func requireChainError(t *testing.T, err error, want string) {
	t.Helper()
	if !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("expected ErrChainInvalid, got %v", err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("expected error to mention %q, got %q", want, err.Error())
	}
}

func TestValidateChain_RejectsEmptyChain(t *testing.T) {
	err := ValidateChain(nil, chainTenant, uuid.New())
	requireChainError(t, err, "empty")
}

func TestValidateChain_RejectsNilAtRoot(t *testing.T) {
	err := ValidateChain([]*models.Delegation{nil}, chainTenant, uuid.New())
	requireChainError(t, err, "nil delegation at depth 0")
}

func TestValidateChain_RejectsNilMidChain(t *testing.T) {
	agent := uuid.New()
	root := delegation(0, models.ActionTierDestructive, nil)
	linkChain(chainTenant, agent, root)

	err := ValidateChain([]*models.Delegation{root, nil}, chainTenant, agent)
	requireChainError(t, err, "nil delegation at index")
}

func TestValidateChain_RejectsNonRootFirstElement(t *testing.T) {
	agent := uuid.New()
	root := delegation(0, models.ActionTierDestructive, nil)
	linkChain(chainTenant, agent, root)
	notARoot := uuid.New()
	root.ParentDelegationID = &notARoot // the one corrupted field

	err := ValidateChain([]*models.Delegation{root}, chainTenant, agent)
	requireChainError(t, err, "is not a root")
}

func TestValidateChain_RejectsRootWithNonZeroDepth(t *testing.T) {
	agent := uuid.New()
	root := delegation(0, models.ActionTierDestructive, nil)
	linkChain(chainTenant, agent, root)
	root.Depth = 3 // the one corrupted field

	err := ValidateChain([]*models.Delegation{root}, chainTenant, agent)
	// "claims depth" alone also appears in the depth-skip message; pin the
	// exact text this specific check emits so a mutant that deletes this
	// check but leaves depth-skip intact cannot slip through on wording.
	requireChainError(t, err, fmt.Sprintf("root %s claims depth %d", root.ID, root.Depth))
}

func TestValidateChain_RejectsTenantMismatchAtRoot(t *testing.T) {
	agent := uuid.New()
	root := delegation(0, models.ActionTierDestructive, nil)
	linkChain(chainTenant, agent, root)
	root.TenantID = "tenant-b" // the one corrupted field

	err := ValidateChain([]*models.Delegation{root}, chainTenant, agent)
	requireChainError(t, err, "belongs to tenant")
}

// The tenant check runs inside the loop for every index, not just the root —
// a chain whose root matches but whose second hop belongs to a different
// tenant is the "mixing tenants mid-chain" shape from the incident this
// validator exists to close. A guard that special-cased index 0 (checking the
// root's tenant but not the rest) would pass RejectsTenantMismatchAtRoot and
// still miss this.
func TestValidateChain_RejectsTenantMismatchMidChain(t *testing.T) {
	agent := uuid.New()
	root := delegation(0, models.ActionTierDestructive, nil)
	child := delegation(1, models.ActionTierDestructive, nil)
	linkChain(chainTenant, agent, root, child)
	child.TenantID = "tenant-b" // the one corrupted field; root is untouched

	err := ValidateChain([]*models.Delegation{root, child}, chainTenant, agent)
	requireChainError(t, err, "belongs to tenant")
}

func TestValidateChain_RejectsWrongRootDelegationID(t *testing.T) {
	agent := uuid.New()
	root := delegation(0, models.ActionTierDestructive, nil)
	linkChain(chainTenant, agent, root)
	root.RootDelegationID = uuid.New() // the one corrupted field: no longer self

	err := ValidateChain([]*models.Delegation{root}, chainTenant, agent)
	requireChainError(t, err, "claims root")
}

func TestValidateChain_RejectsMissingParentPointer(t *testing.T) {
	agent := uuid.New()
	root := delegation(0, models.ActionTierDestructive, nil)
	child := delegation(1, models.ActionTierDestructive, nil)
	linkChain(chainTenant, agent, root, child)
	child.ParentDelegationID = nil // the one corrupted field

	err := ValidateChain([]*models.Delegation{root, child}, chainTenant, agent)
	requireChainError(t, err, "has no parent")
}

func TestValidateChain_RejectsParentPointingAtWrongDelegation(t *testing.T) {
	agent := uuid.New()
	root := delegation(0, models.ActionTierDestructive, nil)
	child := delegation(1, models.ActionTierDestructive, nil)
	linkChain(chainTenant, agent, root, child)
	orphan := uuid.New()
	child.ParentDelegationID = &orphan // the one corrupted field: points nowhere

	err := ValidateChain([]*models.Delegation{root, child}, chainTenant, agent)
	requireChainError(t, err, "claims parent")
}

func TestValidateChain_RejectsDepthSkip(t *testing.T) {
	agent := uuid.New()
	root := delegation(0, models.ActionTierDestructive, nil)
	child := delegation(1, models.ActionTierDestructive, nil)
	linkChain(chainTenant, agent, root, child)
	child.Depth = 2 // the one corrupted field: skips depth 1 entirely

	err := ValidateChain([]*models.Delegation{root, child}, chainTenant, agent)
	requireChainError(t, err, "predecessor is at")
}

func TestValidateChain_RejectsActingDelegationWrongAgent(t *testing.T) {
	requester := uuid.New()
	root := delegation(0, models.ActionTierDestructive, nil)
	child := delegation(1, models.ActionTierDestructive, nil)
	linkChain(chainTenant, requester, root, child)
	child.AgentID = uuid.New() // the one corrupted field: issued to someone else

	err := ValidateChain([]*models.Delegation{root, child}, chainTenant, requester)
	requireChainError(t, err, "issued to agent")
}

func TestValidateChain_AcceptsValidThreeHopChain(t *testing.T) {
	agent := uuid.New()
	root := delegation(0, models.ActionTierDestructive, nil)
	mid := delegation(1, models.ActionTierDestructive, nil)
	leaf := delegation(2, models.ActionTierDestructive, nil)
	linkChain(chainTenant, agent, root, mid, leaf)

	if err := ValidateChain([]*models.Delegation{root, mid, leaf}, chainTenant, agent); err != nil {
		t.Fatalf("a genuine three-hop lineage must validate, got %v", err)
	}
}

func TestValidateChain_AcceptsValidSingleHopRoot(t *testing.T) {
	agent := uuid.New()
	root := delegation(0, models.ActionTierDestructive, nil)
	linkChain(chainTenant, agent, root)

	if err := ValidateChain([]*models.Delegation{root}, chainTenant, agent); err != nil {
		t.Fatalf("a genuine single-hop root must validate, got %v", err)
	}
}
