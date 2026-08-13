package pdpgrpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"

	"stratium/internal/store"
	"stratium/internal/token"
	"stratium/pkg/models"
)

// freshECKeyPEM generates a new random P-256 key and writes it, PEM-encoded,
// to a fresh file under t.TempDir(), returning its path — never a fixture
// committed to the repo, and never reused across tests: a genuinely distinct
// key per call is what makes a later cross-key assertion
// (TestIssueToken_SignsWithCurrentKeyNotPrevious) mean anything, the same
// discipline internal/token's own generateECKey doc comment describes and
// this project has been bitten by getting wrong before.
func freshECKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// testSigner returns a real *token.Signer backed by a freshly generated,
// current-only EC key. Used wherever a test needs to prove a token this
// package issued is actually verifiable, not merely that some string came
// back — internal/token.Signer is Task 1's own tested implementation, and
// using it here directly (rather than a fake that merely claims to sign) is
// what makes TestCreateDelegation_ReturnsVerifiableTokenNamingTheDelegation
// and TestIssueToken_ReturnsVerifiableTokenNamingTheDelegation genuine
// end-to-end proofs instead of tests of this package's own mock.
func testSigner(t *testing.T) *token.Signer {
	t.Helper()
	signer, err := token.Load(freshECKeyPEM(t), "")
	if err != nil {
		t.Fatalf("token.Load() = %v, want success", err)
	}
	return signer
}

// claimKeys returns claims' keys, sorted, so two claim sets can be compared
// for exact equality regardless of Go's randomized map iteration order.
func claimKeys(claims jwt.MapClaims) []string {
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// identifyingClaimKeys is the complete set tokenClaims must produce: the
// delegation id, the tenant, an issued-at, an expiry, and a token id — spec
// §4.7.1 K3's "the minimum that identifies, and nothing more." Declared once
// so every test asserting this set compares against the same slice rather
// than each retyping (and risking a typo silently diverging from) the same
// five strings. Alphabetical (exp, iat, jti, sub, tenant_id) to match
// claimKeys' own sorted output.
var identifyingClaimKeys = []string{expiryClaim, issuedAtClaim, tokenIDClaim, subjectClaim, tenantIDClaim}

// TestTokenClaims_CarriesExactlyTheIdentifyingFields is the direct,
// narrowest-scope proof of K3: tokenClaims' output key set is EXACTLY the
// five identifying fields, no more and no fewer. Exact-set comparison,
// not a check for the absence of one or two specifically-named scope keys
// (e.g. "no max_action_tier") — a narrower assertion would catch the
// mutation this task's brief names ("put the tier ceiling in the claims")
// but miss the same defect under any other field name (approved_tools,
// classification_caps, resource_constraints, or a name nobody has thought
// of yet). This is the test the brief calls for explicitly: "assert that
// explicitly, since it is the property K3 rests on."
func TestTokenClaims_CarriesExactlyTheIdentifyingFields(t *testing.T) {
	delegationID := uuid.New()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(time.Hour)

	claims := tokenClaims(delegationID, "tenant-xyz", now, expiresAt)

	if got := claimKeys(claims); !slices.Equal(got, identifyingClaimKeys) {
		t.Fatalf("claim keys = %v, want exactly %v", got, identifyingClaimKeys)
	}
	if got := claims[subjectClaim]; got != delegationID.String() {
		t.Errorf("sub = %v, want %s", got, delegationID)
	}
	if got := claims[tenantIDClaim]; got != "tenant-xyz" {
		t.Errorf("tenant_id = %v, want %q", got, "tenant-xyz")
	}
	if got := claims[issuedAtClaim]; got != now.Unix() {
		t.Errorf("iat = %v, want %d", got, now.Unix())
	}
	if got := claims[expiryClaim]; got != expiresAt.Unix() {
		t.Errorf("exp = %v, want %d", got, expiresAt.Unix())
	}
}

// A token id that never changed between issuances would make two tokens for
// the same delegation indistinguishable from each other — useless for
// telling a re-issued token apart from the one it replaced.
func TestTokenClaims_TokenIDUniquePerCall(t *testing.T) {
	delegationID := uuid.New()
	now := time.Now()

	a := tokenClaims(delegationID, "tenant-xyz", now, now.Add(time.Hour))
	b := tokenClaims(delegationID, "tenant-xyz", now, now.Add(time.Hour))

	if a[tokenIDClaim] == b[tokenIDClaim] {
		t.Errorf("jti = %v for both calls, want two distinct token ids", a[tokenIDClaim])
	}
}

func TestClampTokenExpiry_RequestedWithinDelegationLifetime_Unclamped(t *testing.T) {
	delegationExpiresAt := time.Now().Add(time.Hour)
	requested := time.Now().Add(10 * time.Minute)

	expiry, clamped := clampTokenExpiry(requested, delegationExpiresAt)
	if clamped {
		t.Error("clamped = true, want false: requested is well within the delegation's own lifetime")
	}
	if !expiry.Equal(requested) {
		t.Errorf("expiry = %v, want %v (the requested value, unchanged)", expiry, requested)
	}
}

// The scenario the brief calls "the one that matters": a requested expiry
// that would outlive the delegation must be cut back to the delegation's
// own expiry, not granted as asked.
func TestClampTokenExpiry_RequestedBeyondDelegationLifetime_Clamped(t *testing.T) {
	delegationExpiresAt := time.Now().Add(5 * time.Minute)
	requested := time.Now().Add(time.Hour)

	expiry, clamped := clampTokenExpiry(requested, delegationExpiresAt)
	if !clamped {
		t.Error("clamped = false, want true: requested exceeds the delegation's own expiry")
	}
	if !expiry.Equal(delegationExpiresAt) {
		t.Errorf("expiry = %v, want %v (the delegation's own expiry, not the longer requested value)",
			expiry, delegationExpiresAt)
	}
}

// Equal must NOT report clamped=true — CreateDelegation calls this with
// requested == delegationExpiresAt exactly (mintToken's doc comment), and
// that ordinary, unclamped case must not be misreported as having been cut
// short.
func TestClampTokenExpiry_RequestedEqualsDelegationLifetime_Unclamped(t *testing.T) {
	same := time.Now().Add(30 * time.Minute)

	expiry, clamped := clampTokenExpiry(same, same)
	if clamped {
		t.Error("clamped = true, want false: requested exactly equals the delegation's expiry, not beyond it")
	}
	if !expiry.Equal(same) {
		t.Errorf("expiry = %v, want %v", expiry, same)
	}
}

// activeDelegation returns a delegation fixture that is neither revoked nor
// expired at the given instant — the "may re-issue" baseline every
// IssueToken success-path test starts from and every failure-path test
// mutates exactly one field away from.
func activeDelegation(id uuid.UUID, now time.Time) *models.Delegation {
	return &models.Delegation{
		ID:        id,
		TenantID:  testTenant,
		AgentID:   uuid.New(),
		ExpiresAt: now.Add(time.Hour),
	}
}

// TestIssueToken_SignsWithCurrentKeyNotPrevious closes a gap mutation
// testing surfaced: internal/token.Signer.Verify deliberately accepts a
// token signed by EITHER the current or the previous key (K1's rotation
// promise — TestVerify_PreviousKeySignedToken_Verifies), so round-tripping
// a token through the SAME signer that issued it (as every other test in
// this file does) cannot distinguish "signed by current" from "signed by
// previous" — Verify succeeding proves only "signed by a key this Signer
// trusts," not which one. This test can, because it checks the issued
// token against a SECOND, independently loaded signer that was given only
// the current key (no previous at all): that verifier has nothing to fall
// back to, so it accepts the token only if mintToken really did sign with
// current. Both signerWithBothKeys and currentOnlyVerifier are loaded from
// the SAME current-key file — a successful Verify here is attributable
// only to "signed by current," never to two independently generated keys
// happening to agree.
//
// Mutation testing found this survives as a true gap from THIS package's
// own suite (though not from internal/token's own
// TestSigner_PreviousKeyDoesNotImplementCryptoSigner /
// TestSigner_ExactlyOnePrivateKeyField, which catch the same defect one
// layer down) — see the task report for the full account.
func TestIssueToken_SignsWithCurrentKeyNotPrevious(t *testing.T) {
	currentPath := freshECKeyPEM(t)
	previousPath := freshECKeyPEM(t) // a genuinely different key, not the same file reused
	signerWithBothKeys, err := token.Load(currentPath, previousPath)
	if err != nil {
		t.Fatalf("token.Load(current+previous) = %v, want success", err)
	}
	currentOnlyVerifier, err := token.Load(currentPath, "")
	if err != nil {
		t.Fatalf("token.Load(current only) = %v, want success", err)
	}

	delegationID := uuid.New()
	now := time.Now()
	fs := &fakeStore{delegation: activeDelegation(delegationID, now)}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), signerWithBothKeys)

	resp, err := srv.IssueToken(context.Background(), &IssueTokenRequest{
		DelegationId: delegationID.String(),
		TtlSeconds:   600,
	})
	if err != nil {
		t.Fatalf("IssueToken() error = %v, want success", err)
	}

	if _, err := currentOnlyVerifier.Verify(resp.GetToken()); err != nil {
		t.Fatalf("a token issued while a previous key was also configured does not verify against "+
			"the current key alone: %v — mintToken must always sign with the current key, never previous", err)
	}
}

func TestIssueToken_ReturnsVerifiableTokenNamingTheDelegation(t *testing.T) {
	signer := testSigner(t)
	delegationID := uuid.New()
	now := time.Now()
	fs := &fakeStore{delegation: activeDelegation(delegationID, now)}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), signer)

	resp, err := srv.IssueToken(context.Background(), &IssueTokenRequest{
		DelegationId: delegationID.String(),
		TtlSeconds:   600,
	})
	if err != nil {
		t.Fatalf("IssueToken() error = %v, want success", err)
	}
	if resp.GetToken() == "" {
		t.Fatal("IssueToken() returned an empty token")
	}

	claims, err := signer.Verify(resp.GetToken())
	if err != nil {
		t.Fatalf("Verify() of the issued token = %v, want success", err)
	}
	if got := claims[subjectClaim]; got != delegationID.String() {
		t.Errorf("token sub = %v, want %s", got, delegationID)
	}
	if got := claims[tenantIDClaim]; got != testTenant {
		t.Errorf("token tenant_id = %v, want %q", got, testTenant)
	}
}

// The requested-TTL-is-longer scenario, over the real RPC: a delegation
// with five minutes left, a caller asking for an hour, and a response that
// must say plainly it did not grant the hour.
func TestIssueToken_ClampsExpiryToDelegationWhenRequestedTTLIsLonger(t *testing.T) {
	signer := testSigner(t)
	delegationID := uuid.New()
	now := time.Now()
	shortLived := activeDelegation(delegationID, now)
	shortLived.ExpiresAt = now.Add(5 * time.Minute)
	fs := &fakeStore{delegation: shortLived}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), signer)

	resp, err := srv.IssueToken(context.Background(), &IssueTokenRequest{
		DelegationId: delegationID.String(),
		TtlSeconds:   3600, // asks for an hour; the delegation only has 5 minutes left
	})
	if err != nil {
		t.Fatalf("IssueToken() error = %v, want success", err)
	}
	if !resp.GetClampedToDelegationExpiry() {
		t.Error("ClampedToDelegationExpiry = false, want true: the requested TTL exceeds the delegation's own life")
	}
	got := resp.GetExpiresAt().AsTime()
	if got.After(shortLived.ExpiresAt) {
		t.Errorf("token expires_at = %v, is after the delegation's own expires_at %v", got, shortLived.ExpiresAt)
	}
	if !got.Equal(shortLived.ExpiresAt) {
		t.Errorf("token expires_at = %v, want exactly the delegation's expires_at %v", got, shortLived.ExpiresAt)
	}

	claims, err := signer.Verify(resp.GetToken())
	if err != nil {
		t.Fatalf("Verify() of the issued token = %v, want success", err)
	}
	if exp, ok := claims[expiryClaim].(float64); !ok || int64(exp) > shortLived.ExpiresAt.Unix() {
		t.Errorf("token's own exp claim = %v, want at most %d (the delegation's expiry)",
			claims[expiryClaim], shortLived.ExpiresAt.Unix())
	}
}

func TestIssueToken_RequestedTTLWithinDelegationLifetime_NotClamped(t *testing.T) {
	signer := testSigner(t)
	delegationID := uuid.New()
	now := time.Now()
	fs := &fakeStore{delegation: activeDelegation(delegationID, now)} // one hour of life
	srv := NewServer(fs, denyAllPolicy(), testConfig(), signer)

	resp, err := srv.IssueToken(context.Background(), &IssueTokenRequest{
		DelegationId: delegationID.String(),
		TtlSeconds:   60, // one minute, comfortably under the delegation's remaining hour
	})
	if err != nil {
		t.Fatalf("IssueToken() error = %v, want success", err)
	}
	if resp.GetClampedToDelegationExpiry() {
		t.Error("ClampedToDelegationExpiry = true, want false: the requested TTL is well within the delegation's life")
	}
}

// The tenant claim comes from server configuration, the same single source
// of truth every audit entry and Decide already use (server.go's own "config
// only. Never req" comment) — never from the loaded delegation row's own
// tenant_id column. RLS makes the two values agree in every real deployment,
// which is exactly why this fixture deliberately makes them DISAGREE: only a
// mismatched fixture can prove which of the two the code actually reads,
// the same fixture-mixup concern this project has been bitten by before
// (see internal/token's own generateECKey doc comment).
func TestIssueToken_ClaimsTenantFromConfigNotDelegationRow(t *testing.T) {
	signer := testSigner(t)
	delegationID := uuid.New()
	now := time.Now()
	d := activeDelegation(delegationID, now)
	d.TenantID = "a-different-tenant-than-config"
	fs := &fakeStore{delegation: d}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), signer)

	resp, err := srv.IssueToken(context.Background(), &IssueTokenRequest{
		DelegationId: delegationID.String(),
		TtlSeconds:   60,
	})
	if err != nil {
		t.Fatalf("IssueToken() error = %v, want success", err)
	}
	claims, err := signer.Verify(resp.GetToken())
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if got := claims[tenantIDClaim]; got != testTenant {
		t.Errorf("token tenant_id = %v, want %q (the server's configured tenant, not the row's own %q)",
			got, testTenant, d.TenantID)
	}
}

func TestIssueToken_RevokedDelegation_PermissionDenied(t *testing.T) {
	delegationID := uuid.New()
	now := time.Now()
	d := activeDelegation(delegationID, now)
	d.Revoked = true
	fs := &fakeStore{delegation: d}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.IssueToken(context.Background(), &IssueTokenRequest{
		DelegationId: delegationID.String(),
		TtlSeconds:   60,
	})
	if resp != nil {
		t.Fatalf("IssueToken() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.PermissionDenied)
}

func TestIssueToken_ExpiredDelegation_PermissionDenied(t *testing.T) {
	delegationID := uuid.New()
	now := time.Now()
	d := activeDelegation(delegationID, now)
	d.ExpiresAt = now.Add(-time.Minute) // expired one minute ago
	fs := &fakeStore{delegation: d}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.IssueToken(context.Background(), &IssueTokenRequest{
		DelegationId: delegationID.String(),
		TtlSeconds:   60,
	})
	if resp != nil {
		t.Fatalf("IssueToken() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.PermissionDenied)
}

// A delegation for another tenant is indistinguishable from a missing one —
// RLS's own design (store's package doc) — so the fake reports ErrNotFound
// exactly as it would for a genuinely unknown id, matching how every other
// cross-tenant scenario in this package is exercised (e.g.
// TestCreateDelegation_UnknownAgent_NotFound).
func TestIssueToken_UnknownOrCrossTenantDelegation_NotFound(t *testing.T) {
	delegationID := uuid.New()
	fs := &fakeStore{delegationErr: fmt.Errorf("%w: delegation %s", store.ErrNotFound, delegationID)}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.IssueToken(context.Background(), &IssueTokenRequest{
		DelegationId: delegationID.String(),
		TtlSeconds:   60,
	})
	if resp != nil {
		t.Fatalf("IssueToken() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.NotFound)
}

func TestIssueToken_StoreLoadFailure_Internal(t *testing.T) {
	delegationID := uuid.New()
	fs := &fakeStore{delegationErr: errors.New("connection reset")}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.IssueToken(context.Background(), &IssueTokenRequest{
		DelegationId: delegationID.String(),
		TtlSeconds:   60,
	})
	if resp != nil {
		t.Fatalf("IssueToken() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.Internal)
}

// Invalid input must be rejected before any store call, the same discipline
// TestDecide_InvalidInput_InvalidArgument and
// TestCreateDelegation_InvalidInput_InvalidArgument already hold their own
// RPCs to: fs.calls == 0 proves "do not proceed," not just that the code
// happened to come back InvalidArgument.
func TestIssueToken_InvalidInput_InvalidArgument(t *testing.T) {
	cases := map[string]*IssueTokenRequest{
		"empty delegation_id":     {DelegationId: "", TtlSeconds: 60},
		"malformed delegation_id": {DelegationId: "not-a-uuid", TtlSeconds: 60},
		"zero delegation_id":      {DelegationId: uuid.Nil.String(), TtlSeconds: 60},
		"zero ttl_seconds":        {DelegationId: uuid.New().String(), TtlSeconds: 0},
		"negative ttl_seconds":    {DelegationId: uuid.New().String(), TtlSeconds: -1},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			fs := &fakeStore{}
			srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

			resp, err := srv.IssueToken(context.Background(), req)
			if resp != nil {
				t.Fatalf("IssueToken() response = %+v, want nil", resp)
			}
			wantCode(t, err, codes.InvalidArgument)
			if fs.calls != 0 {
				t.Errorf("store was called %d times, want 0 — invalid input must not proceed to a lookup", fs.calls)
			}
		})
	}
}

// The mutation this task's brief names explicitly: a signing failure must
// fail the call outright, never fall back to a response with an empty
// token — "no path returns a delegation id without a token where a token
// was expected" applies to a re-issued token exactly as it does to
// CreateDelegation's own (see TestCreateDelegation_SigningFailure_
// ReturnsErrorAndNoToken for that RPC's version of this same property).
func TestIssueToken_SigningFailure_Internal(t *testing.T) {
	delegationID := uuid.New()
	now := time.Now()
	fs := &fakeStore{delegation: activeDelegation(delegationID, now)}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{signErr: errors.New("hsm unavailable")})

	resp, err := srv.IssueToken(context.Background(), &IssueTokenRequest{
		DelegationId: delegationID.String(),
		TtlSeconds:   60,
	})
	if resp != nil {
		t.Fatalf("IssueToken() response = %+v, want nil: no token may escape a signing failure", resp)
	}
	wantCode(t, err, codes.Internal)
}
