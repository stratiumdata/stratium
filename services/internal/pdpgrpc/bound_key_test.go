package pdpgrpc

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"

	"github.com/stratiumdata/stratium/pkg/models"
)

// A delegation is bound to at most one key. Once it is, every token path
// refuses a token that is not bound to that key, the delegation's own first
// bearer token included. These tests share one shape: fs.boundKey is the key
// the store has recorded for the delegation.

func TestIssueToken_FirstBindingIsRecordedOnTheDelegation(t *testing.T) {
	signer := testSigner(t)
	delegationID := uuid.New()
	jwk, jkt := freshJWK(t)
	fs := &fakeStore{delegation: activeDelegation(delegationID, time.Now())}

	_, err := NewServer(fs, denyAllPolicy(), testConfig(), signer).IssueToken(context.Background(),
		&IssueTokenRequest{DelegationId: delegationID.String(), TtlSeconds: 600,
			Token: priorToken(t, signer, delegationID, ""), DpopJwk: &jwk})
	if err != nil {
		t.Fatalf("IssueToken() error = %v, want success", err)
	}
	if fs.boundKey != jkt {
		t.Errorf("delegation's recorded key = %q, want %q", fs.boundKey, jkt)
	}
}

func TestIssueToken_BoundDelegationRefusesItsOwnBearerToken(t *testing.T) {
	signer := testSigner(t)
	delegationID := uuid.New()
	ownerJWK, ownerJKT := freshJWK(t)
	thiefJWK, _ := freshJWK(t)
	bearer := priorToken(t, signer, delegationID, "") // the first token, never bound

	issue := func(jwk *string) (*IssueTokenResponse, *fakeStore, error) {
		fs := &fakeStore{delegation: activeDelegation(delegationID, time.Now()), boundKey: ownerJKT}
		resp, err := NewServer(fs, denyAllPolicy(), testConfig(), signer).IssueToken(context.Background(),
			&IssueTokenRequest{DelegationId: delegationID.String(), TtlSeconds: 600, Token: bearer, DpopJwk: jwk})
		return resp, fs, err
	}

	if resp, _, err := issue(nil); resp != nil || err == nil {
		t.Fatalf("no key: got resp=%v err=%v, want a refusal (would mint another bearer token)", resp, err)
	} else {
		wantCode(t, err, codes.PermissionDenied)
	}
	resp, fs, err := issue(&thiefJWK)
	if resp != nil || err == nil {
		t.Fatalf("another key: got resp=%v err=%v, want a refusal (would bind a second key)", resp, err)
	}
	wantCode(t, err, codes.PermissionDenied)
	if fs.boundKey != ownerJKT {
		t.Errorf("recorded key changed to %q, want it left at %q", fs.boundKey, ownerJKT)
	}

	resp, _, err = issue(&ownerJWK)
	if err != nil {
		t.Fatalf("the bound key: IssueToken() error = %v, want success", err)
	}
	claims, err := signer.Verify(resp.GetToken())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got, _ := tokenThumbprint(claims); got != ownerJKT {
		t.Errorf("jkt = %q, want %q", got, ownerJKT)
	}
}

func TestDecide_BoundDelegationDeniesItsOwnBearerToken(t *testing.T) {
	fs, req, delegationID := decideTokenFixture(t)
	signer := testSigner(t)
	now := time.Now()
	req.Token = signRealToken(t, signer, delegationID, now, now.Add(time.Hour))
	_, fs.boundKey = freshJWK(t)

	resp, err := NewServer(fs, denyAllPolicy(), testConfig(), signer).Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v, want an audited DENY", err)
	}
	if resp.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("Effect = %v, want DENY", resp.GetEffect())
	}
	if !strings.Contains(resp.GetReason(), "bound to a key") {
		t.Errorf("Reason = %q, want it to say the delegation is bound to a key", resp.GetReason())
	}
	if len(fs.appended) != 1 {
		t.Errorf("audit entries = %d, want 1", len(fs.appended))
	}
}

func TestCreateDelegation_WithAKeyIsBoundFromTheStart(t *testing.T) {
	fs, req, _ := wellFormedDelegationFixture()
	jwk, jkt := freshJWK(t)
	req.DpopJwk = &jwk
	signer := testSigner(t)
	srv := NewServer(fs, singleFakeLanguagePolicy(fakePolicyEngine{set: permissiveGrantSet()}), testConfig(), signer)

	resp, err := srv.CreateDelegation(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateDelegation() error = %v", err)
	}
	if fs.boundKey != jkt {
		t.Errorf("delegation's recorded key = %q, want %q", fs.boundKey, jkt)
	}
	claims, err := signer.Verify(resp.GetToken())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got, _ := tokenThumbprint(claims); got != jkt {
		t.Errorf("first token's jkt = %q, want %q: no bearer token may be issued for a bound delegation", got, jkt)
	}
}

func TestCreateDelegation_UnusableKeyIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	fs, req, _ := wellFormedDelegationFixture()
	bad := `{"kty":"nope"}`
	req.DpopJwk = &bad
	srv := newDelegationServer(fs, permissiveGrantSet())

	_, err := srv.CreateDelegation(context.Background(), req)
	wantCode(t, err, codes.InvalidArgument)
	if len(fs.created) != 0 {
		t.Errorf("delegation rows created = %d, want 0", len(fs.created))
	}
}

func TestCreateDelegation_BoundParentCannotHaveChildren(t *testing.T) {
	fs, req, _ := wellFormedDelegationFixture()
	parentID := uuid.New()
	req.ParentDelegationId = parentID.String()
	req.ParentToken = parentID.String() // fakeSigner: the parent's own bearer token
	fs.chain = []*models.Delegation{{
		ID: parentID, RootDelegationID: parentID, UserID: "alice@example.com",
		MaxActionTier: models.ActionTierDestructive, ApprovedTools: []string{"Bash", "Read"},
	}}
	_, fs.boundKey = freshJWK(t)
	srv := newDelegationServer(fs, permissiveGrantSet())

	_, err := srv.CreateDelegation(context.Background(), req)
	wantCode(t, err, codes.PermissionDenied)
	if len(fs.created) != 0 {
		t.Errorf("delegation rows created = %d, want 0", len(fs.created))
	}
}

func TestReportToolUse_RefusedForABoundDelegation(t *testing.T) {
	_, jkt := freshJWK(t)
	tests := map[string]struct {
		tokenJKT, boundKey string
	}{
		"a key-bound token, which this method cannot check a proof for": {jkt, jkt},
		"the bearer token of a delegation since bound to a key":         {"", jkt},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			fs, _, delegationID := decideTokenFixture(t)
			fs.boundKey = tt.boundKey
			signer := testSigner(t)
			tok := liveToken(t, signer, delegationID, tt.tokenJKT)

			resp, err := NewServer(fs, denyAllPolicy(), testConfig(), signer).ReportToolUse(context.Background(),
				&ReportToolUseRequest{Token: tok, Tool: "Bash", RawInput: `{"command":"rm -rf /"}`})
			if resp != nil {
				t.Fatalf("ReportToolUse() = %v, want a refusal", resp)
			}
			wantCode(t, err, codes.PermissionDenied)
			if len(fs.appended) != 0 {
				t.Errorf("audit entries = %d, want 0", len(fs.appended))
			}
		})
	}
}

func TestGetApproval_AnsweredOnlyToTheSessionWaitingOnIt(t *testing.T) {
	fs, a := approvalFixture()
	a.DelegationID = uuid.New()
	srv := NewServer(fs, escalationPolicy(), testConfig(), &fakeSigner{})

	_, err := srv.GetApproval(context.Background(), &GetApprovalRequest{ApprovalId: a.ID.String()})
	wantCode(t, err, codes.Unauthenticated)

	_, err = srv.GetApproval(context.Background(), &GetApprovalRequest{ApprovalId: a.ID.String(), Token: "not-a-token"})
	wantCode(t, err, codes.Unauthenticated)

	// A genuine token for another delegation learns nothing, not even that
	// the approval exists.
	_, err = srv.GetApproval(context.Background(), &GetApprovalRequest{ApprovalId: a.ID.String(), Token: uuid.NewString()})
	wantCode(t, err, codes.NotFound)

	resp, err := srv.GetApproval(context.Background(), &GetApprovalRequest{ApprovalId: a.ID.String(), Token: a.DelegationID.String()})
	if err != nil || resp.GetStatus() != a.Status {
		t.Fatalf("GetApproval() with the delegation's own token = %v, %v; want status %q", resp, err, a.Status)
	}
}

// A token bound to some other key than the one recorded for the delegation
// is refused even with a valid proof for its own key. IssueToken never mints
// one once a key is recorded, but one issued before the delegation's key was
// recorded can still be in circulation until it expires.
func TestDecide_TokenBoundToAnotherKeyThanTheDelegations(t *testing.T) {
	t.Run("another key is denied", func(t *testing.T) {
		f := newBoundFixture(t)
		_, f.fs.boundKey = freshJWK(t)

		resp := f.decide(t)
		if resp.GetEffect() != Effect_EFFECT_DENY || !strings.Contains(resp.GetReason(), "bound to a key") {
			t.Fatalf("Decide() = %v (%s), want DENY naming the key binding", resp.GetEffect(), resp.GetReason())
		}
	})
	t.Run("the recorded key is allowed", func(t *testing.T) {
		f := newBoundFixture(t)
		claims, err := f.signer.Verify(f.req.GetToken())
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		f.fs.boundKey, _ = tokenThumbprint(claims)

		if resp := f.decide(t); resp.GetEffect() != Effect_EFFECT_ALLOW {
			t.Fatalf("Decide() = %v (%s), want ALLOW", resp.GetEffect(), resp.GetReason())
		}
	})
}
