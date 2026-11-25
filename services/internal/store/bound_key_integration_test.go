//go:build integration

package store_test

import (
	"crypto/ecdsa"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
	"github.com/stratiumdata/stratium/internal/store"
	"github.com/stratiumdata/stratium/pkg/models"
)

func publicJWK(t *testing.T, key *ecdsa.PrivateKey) *string {
	t.Helper()
	doc, err := (&jose.JSONWebKey{Key: key.Public()}).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal public jwk: %v", err)
	}
	jwk := string(doc)
	return &jwk
}

// A delegation is bound to at most one key, against the real schema: the
// first key-bound token records the key (migration 000024), and from then on
// the delegation's own first bearer token is refused on every path. Recording
// the key does not bump the tenant's epoch; revoking the delegation still
// does.
func TestIntegration_BoundKey_FirstBindingPinsTheDelegation(t *testing.T) {
	const tenant = "tenant-bound-key-pin-integration"
	const subject = "bound-key@example.com"
	srv, _ := escalationServer(t, tenant)
	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "bound-key-agent", models.TrustTierPlatformTrusted)

	root := issueRoot(t, srv, agentID, subject)
	bearer := root.GetToken()
	issue := func(jwk *string) (*pdpgrpc.IssueTokenResponse, error) {
		return srv.IssueToken(t.Context(), &pdpgrpc.IssueTokenRequest{
			DelegationId: root.GetDelegationId(), TtlSeconds: 600, Token: bearer, DpopJwk: jwk,
		})
	}

	// Revoking another delegation first gives the tenant an epoch row to
	// compare against.
	other := issueRoot(t, srv, agentID, subject)
	otherID := uuid.MustParse(other.GetDelegationId())
	if _, err := store.New(testDB, tenant).RevokeDelegation(t.Context(), otherID, "integration-operator", time.Now().UTC()); err != nil {
		t.Fatalf("RevokeDelegation: %v", err)
	}
	before, exists := readTenantEpoch(t, tenant)
	if !exists {
		t.Fatal("no tenant_epoch row after a revocation: the delete/update trigger split lost the update half")
	}

	owner, thief := dpopKey(t), dpopKey(t)
	if _, err := issue(publicJWK(t, owner)); err != nil {
		t.Fatalf("first binding: IssueToken() error = %v", err)
	}
	if after, _ := readTenantEpoch(t, tenant); after != before {
		t.Errorf("epoch went %d -> %d on recording a key, want it unchanged", before, after)
	}

	if _, err := issue(publicJWK(t, thief)); err == nil {
		t.Error("the bearer token was exchanged for a token bound to a second key")
	} else {
		wantCode(t, err, codes.PermissionDenied)
	}
	if _, err := issue(nil); err == nil {
		t.Error("the bearer token was exchanged for another bearer token after the delegation was bound")
	} else {
		wantCode(t, err, codes.PermissionDenied)
	}
	if _, err := issue(publicJWK(t, owner)); err != nil {
		t.Errorf("the bound key itself: IssueToken() error = %v, want success", err)
	}

	decision, err := srv.Decide(t.Context(), &pdpgrpc.DecideRequest{
		Token: bearer, AgentId: agentID.String(), Subject: subject, Tool: "Bash", RawInput: escalationRawInput,
	})
	if err != nil {
		t.Fatalf("Decide() with the bearer token: %v", err)
	}
	if decision.GetEffect() != pdpgrpc.Effect_EFFECT_DENY || !strings.Contains(decision.GetReason(), "bound to a key") {
		t.Errorf("Decide() with the bearer token = %v (%s), want DENY naming the key binding",
			decision.GetEffect(), decision.GetReason())
	}

	_, err = srv.ReportToolUse(t.Context(), &pdpgrpc.ReportToolUseRequest{Token: bearer, Tool: "Bash", RawInput: "{}"})
	wantCode(t, err, codes.PermissionDenied)

	_, err = srv.CreateDelegation(t.Context(), &pdpgrpc.CreateDelegationRequest{
		Subject: subject, AgentId: agentID.String(),
		ParentDelegationId: root.GetDelegationId(), ParentToken: bearer,
		RequestedScope: &pdpgrpc.RequestedScope{MaxActionTier: int32(models.ActionTierReadOnly), Tools: []string{"Bash"}},
		Purpose:        "child of a bound parent", TtlSeconds: 600,
	})
	wantCode(t, err, codes.PermissionDenied)

	// Revocation still bumps the epoch after the trigger was split in two.
	rootID := uuid.MustParse(root.GetDelegationId())
	if _, err := store.New(testDB, tenant).RevokeDelegation(t.Context(), rootID, "integration-operator", time.Now().UTC()); err != nil {
		t.Fatalf("RevokeDelegation: %v", err)
	}
	assertEpochBumped(t, tenant, before)
}

// A delegation created with a key never has a bearer token at all.
func TestIntegration_BoundKey_CreatedWithAKeyHasNoBearerToken(t *testing.T) {
	const tenant = "tenant-bound-key-create-integration"
	srv, signer := escalationServer(t, tenant)
	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "bound-at-creation-agent", models.TrustTierPlatformTrusted)
	key := dpopKey(t)

	created, err := srv.CreateDelegation(t.Context(), &pdpgrpc.CreateDelegationRequest{
		Subject: "bound-at-creation@example.com", AgentId: agentID.String(),
		RequestedScope: &pdpgrpc.RequestedScope{MaxActionTier: int32(models.ActionTierReadOnly), Tools: []string{"Bash"}},
		Purpose:        "bound at creation", TtlSeconds: 600, DpopJwk: publicJWK(t, key),
	})
	if err != nil {
		t.Fatalf("CreateDelegation() with a key: %v", err)
	}
	claims, err := signer.Verify(created.GetToken())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if _, bound := claims["cnf"]; !bound {
		t.Fatal("the first token carries no cnf claim: a bearer token was issued for a delegation created with a key")
	}
	_, err = srv.IssueToken(t.Context(), &pdpgrpc.IssueTokenRequest{
		DelegationId: created.GetDelegationId(), TtlSeconds: 600, Token: created.GetToken(),
	})
	wantCode(t, err, codes.PermissionDenied)
}
