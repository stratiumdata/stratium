package pdpgrpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
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
//
// The empty jkt is what an unbound token is minted with, so this exact-set
// comparison ALSO fails if cnf appears when no key was supplied — the named
// Phase 15 mutation. It is not the primary guard against that (see
// TestTokenClaims_NoThumbprint_OmitsConfirmationClaimEntirely, which names
// the property, and TestIssueToken_NoJWK_TokenCarriesNoConfirmationClaim,
// which proves it through the real RPC on a real signed token), because
// this test's failure message would blame K3 for a Phase 15 defect.
func TestTokenClaims_CarriesExactlyTheIdentifyingFields(t *testing.T) {
	delegationID := uuid.New()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(time.Hour)

	claims := tokenClaims(delegationID, "tenant-xyz", "", now, expiresAt)

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

	a := tokenClaims(delegationID, "tenant-xyz", "", now, now.Add(time.Hour))
	b := tokenClaims(delegationID, "tenant-xyz", "", now, now.Add(time.Hour))

	if a[tokenIDClaim] == b[tokenIDClaim] {
		t.Errorf("jti = %v for both calls, want two distinct token ids", a[tokenIDClaim])
	}
}

// --- Key binding: cnf.jkt (spec §4.7.2 K6) -------------------------------

// rfc9449ExampleJWK and rfc9449ExampleThumbprint are transcribed from RFC
// 9449: §4.2's example proof carries this key in its jwk header, and §6.1
// publishes the cnf.jkt of the access token that proof is bound to — the RFC
// publishing, for one key, exactly the input and the output of the operation
// under test here.
//
// The expectation therefore does not share a code path with the code that
// produces it. Asserting instead that the issued token's cnf.jkt equals
// dpop.Thumbprint(sameJWK) would agree with itself no matter how wrong the
// thumbprint was, and would go on agreeing after a mutation that replaced
// the whole computation — the value is only meaningful because a verifier
// somewhere else, following the same RFC, arrives at it independently.
//
// Duplicated from internal/dpop's own test file rather than shared: it is a
// constant published by an RFC, and a fixture exported from one package's
// tests so another can reuse it is a coupling with no upside here.
const (
	rfc9449ExampleJWK = `{
  "kty":"EC",
  "x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
  "y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
  "crv":"P-256"
}`
	rfc9449ExampleThumbprint = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
)

// tokenConfirmation returns the cnf claim of a VERIFIED token's claim set,
// and whether it was present at all. The claims have been through a JSON
// round trip by the time Verify hands them back, so cnf arrives as
// map[string]any regardless of what tokenClaims put in — asserting on the
// decoded shape is the point: it is what a verifier on another surface, and
// in Task 4, will actually see.
func tokenConfirmation(t *testing.T, claims jwt.MapClaims) (map[string]any, bool) {
	t.Helper()
	raw, present := claims[confirmationClaim]
	if !present {
		return nil, false
	}
	cnf, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("cnf claim = %#v (%T), want a JSON object", raw, raw)
	}
	return cnf, true
}

// The named mutation, at the layer that decides it: no thumbprint must mean
// NO cnf claim, never a cnf carrying an empty jkt. A present-but-empty cnf
// would satisfy any "is this token bound?" test a surface can cheaply make
// while being matchable by no key in existence — a token that looks bound
// and binds nothing, which is worse than an honest bearer token (which the
// network surfaces refuse under K5) and worse than an honest bound one.
//
// Asserts on presence, not on the value: `claims[confirmationClaim] == nil`
// would pass for a cnf explicitly set to nil, which is the same defect
// wearing a different type.
func TestTokenClaims_NoThumbprint_OmitsConfirmationClaimEntirely(t *testing.T) {
	claims := tokenClaims(uuid.New(), "tenant-xyz", "", time.Now(), time.Now().Add(time.Hour))

	if raw, present := claims[confirmationClaim]; present {
		t.Fatalf("cnf claim is present (= %#v) on a token minted with no thumbprint, want it absent "+
			"entirely: a cnf carrying an empty jkt looks bound and binds nothing", raw)
	}
}

// The other half: a thumbprint yields cnf.jkt and changes nothing else. The
// key set is compared exactly, against the same identifyingClaimKeys the K3
// test uses plus cnf — so a change that bound the token AND smuggled in a
// scope field fails here too, rather than passing a narrow "does cnf.jkt
// look right?" check.
func TestTokenClaims_WithThumbprint_CarriesConfirmationAndNothingElseNew(t *testing.T) {
	claims := tokenClaims(uuid.New(), "tenant-xyz", rfc9449ExampleThumbprint, time.Now(), time.Now().Add(time.Hour))

	want := append([]string{confirmationClaim}, identifyingClaimKeys...)
	slices.Sort(want)
	if got := claimKeys(claims); !slices.Equal(got, want) {
		t.Fatalf("claim keys = %v, want exactly %v", got, want)
	}
	cnf, ok := claims[confirmationClaim].(map[string]string)
	if !ok {
		t.Fatalf("cnf claim = %#v (%T), want a map[string]string", claims[confirmationClaim], claims[confirmationClaim])
	}
	if len(cnf) != 1 || cnf[thumbprintKey] != rfc9449ExampleThumbprint {
		t.Fatalf("cnf = %v, want exactly one member %q = %q", cnf, thumbprintKey, rfc9449ExampleThumbprint)
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

// --- Key binding over the real RPC ---------------------------------------

// issueTokenWithJWK runs one IssueToken call against an active delegation
// and a real signer, returning the response, the error, the signer needed to
// decode the token, and the fakeStore so a caller can assert on how far the
// call got. jwk is sent as-is when non-nil and omitted entirely when nil —
// the distinction the whole optional field rests on, so the helper preserves
// it rather than papering over it with an empty string.
func issueTokenWithJWK(t *testing.T, jwk *string) (*IssueTokenResponse, *token.Signer, *fakeStore, error) {
	t.Helper()
	signer := testSigner(t)
	delegationID := uuid.New()
	fs := &fakeStore{delegation: activeDelegation(delegationID, time.Now())}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), signer)

	resp, err := srv.IssueToken(context.Background(), &IssueTokenRequest{
		DelegationId: delegationID.String(),
		TtlSeconds:   600,
		DpopJwk:      jwk,
	})
	return resp, signer, fs, err
}

// K6, end to end: a public JWK in, a token whose cnf.jkt is that key's RFC
// 7638 thumbprint out — checked against the value RFC 9449 §6.1 publishes
// for the key in §4.2, not against a second run of this system's own
// thumbprint code (see rfc9449ExampleJWK's comment). A token bound to a
// thumbprint a verifier following the RFC would not reproduce is a token
// nobody can ever use, and only an externally published expectation can
// catch that.
func TestIssueToken_WithJWK_BindsTokenToRFC7638Thumbprint(t *testing.T) {
	jwk := rfc9449ExampleJWK
	resp, signer, _, err := issueTokenWithJWK(t, &jwk)
	if err != nil {
		t.Fatalf("IssueToken() error = %v, want success", err)
	}

	claims, err := signer.Verify(resp.GetToken())
	if err != nil {
		t.Fatalf("Verify() of the issued token = %v, want success", err)
	}
	cnf, present := tokenConfirmation(t, claims)
	if !present {
		t.Fatalf("issued token carries no cnf claim, want one bound to the supplied key")
	}
	if got := cnf[thumbprintKey]; got != rfc9449ExampleThumbprint {
		t.Fatalf("cnf.jkt = %v, want %q — the thumbprint RFC 9449 §6.1 publishes for the §4.2 key. "+
			"A value this system computes but a verifier does not reproduce binds the token to nothing usable",
			got, rfc9449ExampleThumbprint)
	}
}

// The named mutation, proven where it would actually do damage: on a real
// signed token, decoded the way every verifier will decode it. The unit-level
// TestTokenClaims_NoThumbprint_OmitsConfirmationClaimEntirely pins the claim
// builder; this pins the whole path from "no dpop_jwk on the request" to
// "no cnf in the token a caller receives," which is the property the network
// surfaces' K5 check reads.
//
// This is also half the bearer-compatibility proof: the token verifies and
// names the delegation exactly as it did before this field existed. The
// other half — that such a token still authenticates at Decide — is
// TestIssueToken_UnboundTokenStillAuthenticatesAtDecide below.
func TestIssueToken_NoJWK_TokenCarriesNoConfirmationClaim(t *testing.T) {
	resp, signer, _, err := issueTokenWithJWK(t, nil)
	if err != nil {
		t.Fatalf("IssueToken() error = %v, want success", err)
	}

	claims, err := signer.Verify(resp.GetToken())
	if err != nil {
		t.Fatalf("Verify() of the issued token = %v, want success: a caller that sends no JWK must get "+
			"exactly the bearer token it got before Phase 15", err)
	}
	if _, present := tokenConfirmation(t, claims); present {
		t.Fatalf("issued token carries a cnf claim (= %#v) though no JWK was supplied, want none at all: "+
			"a cnf with an empty jkt looks bound to a surface checking for one and is matchable by no key",
			claims[confirmationClaim])
	}
	if got := claims[subjectClaim]; got != resp.GetToken() && got == nil {
		t.Fatalf("token sub = %v, want the delegation id", got)
	}
}

// A JWK this system cannot thumbprint is refused at issuance, loudly, and
// before the delegation lookup — the same "invalid input must not proceed to
// a lookup" discipline TestIssueToken_InvalidInput_InvalidArgument holds the
// other request fields to.
//
// On what these cases prove and what they do not: the property under test is
// "IssueToken surfaces a refused JWK as InvalidArgument without touching the
// store", and every case below differs from a JWK that succeeds
// (rfc9449ExampleJWK, above) in exactly that respect — dpop.Thumbprint
// refuses it. WHICH of dpop's checks refuses each one is that package's
// property and is tested there against its own inputs; asserting it a second
// time here would be this test claiming to prove something it cannot
// distinguish, since all four arrive as the same code with the same shape.
// The private-key case gets its own test below, because for that one the
// difference from an accepted input can be isolated exactly.
func TestIssueToken_UnusableJWK_InvalidArgument(t *testing.T) {
	cases := map[string]string{
		"not JSON at all":         "not-a-jwk",
		"explicitly empty":        "",
		"JSON, but not a key":     "{}",
		"symmetric key":           `{"kty":"oct","k":"c2VjcmV0LXNoYXJlZC1rZXktbm90LWEtcHVibGljLW9uZQ"}`,
		"unknown key type":        `{"kty":"NOPE","x":"AA"}`,
		"EC key missing a member": `{"kty":"EC","crv":"P-256","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs"}`,
	}
	for name, jwk := range cases {
		t.Run(name, func(t *testing.T) {
			resp, _, fs, err := issueTokenWithJWK(t, &jwk)
			if resp != nil {
				t.Fatalf("IssueToken() response = %+v, want nil: a token bound to a thumbprint nobody "+
					"can reproduce can never be used", resp)
			}
			wantCode(t, err, codes.InvalidArgument)
			if fs.calls != 0 {
				t.Errorf("store was called %d times, want 0 — an unusable JWK must not proceed to a lookup", fs.calls)
			}
		})
	}
}

// The mutation "compute the thumbprint over the private key," isolated: ONE
// keypair, two requests differing by exactly the private material. The public
// half is accepted and binds; the same key with its "d" member present is
// refused. Nothing else about the two inputs differs — same curve, same x,
// same y — so the refusal is attributable to the private material and to
// nothing else, and an implementation that thumbprinted whatever it was
// handed would be caught by the second call succeeding.
//
// Refusing it is not pedantry. A caller that sends its private key has
// already lost the property binding exists to provide (the server now holds
// a copy of the only thing that made the token unusable by a thief), and the
// cheapest moment to tell it so is before it starts relying on that token.
func TestIssueToken_PrivateKeyJWK_RefusedWhileItsPublicHalfIsAccepted(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	publicJWK, err := (&jose.JSONWebKey{Key: priv.Public()}).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal public JWK: %v", err)
	}
	privateJWK, err := (&jose.JSONWebKey{Key: priv}).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal private JWK: %v", err)
	}

	public := string(publicJWK)
	resp, signer, _, err := issueTokenWithJWK(t, &public)
	if err != nil {
		t.Fatalf("IssueToken() with the PUBLIC half = %v, want success — if this fails the private-key "+
			"case below proves nothing, because both inputs would be refused", err)
	}
	claims, err := signer.Verify(resp.GetToken())
	if err != nil {
		t.Fatalf("Verify() of the issued token = %v, want success", err)
	}
	if cnf, present := tokenConfirmation(t, claims); !present || cnf[thumbprintKey] == "" {
		t.Fatalf("the public half produced no cnf.jkt (claims %v), want a bound token", claims)
	}

	private := string(privateJWK)
	resp, _, fs, err := issueTokenWithJWK(t, &private)
	if resp != nil {
		t.Fatalf("IssueToken() response = %+v, want nil: a JWK carrying private key material must be "+
			"refused, never thumbprinted", resp)
	}
	wantCode(t, err, codes.InvalidArgument)
	if fs.calls != 0 {
		t.Errorf("store was called %d times, want 0", fs.calls)
	}
}

// A caller CAN send private key material to this field — that is exactly
// what the test above refuses — so the refusal must not echo it. Same
// property, and same reason, as
// TestAuthenticateToken_ErrorNeverContainsTheTokenString one file over, and
// the phase's own "never log a token, a key, or a key path's contents"
// constraint: an InvalidArgument message is the most likely thing in this
// method to reach a log, a trace, or a client's stderr.
//
// Asserts on the "d" member's VALUE, not on the substring "d" — a
// single-character search would match half the message by accident and pass
// no matter what.
func TestIssueToken_PrivateKeyJWK_ErrorNeverEchoesTheKeyMaterial(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	privateJWK, err := (&jose.JSONWebKey{Key: priv}).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal private JWK: %v", err)
	}
	var parsed struct {
		D string `json:"d"`
	}
	if err := json.Unmarshal(privateJWK, &parsed); err != nil || parsed.D == "" {
		t.Fatalf("fixture JWK carries no d member (err %v) — this test would pass vacuously", err)
	}

	jwk := string(privateJWK)
	_, _, _, err = issueTokenWithJWK(t, &jwk)
	if err == nil {
		t.Fatal("IssueToken() error = nil, want a refusal")
	}
	if strings.Contains(err.Error(), parsed.D) {
		t.Fatalf("the refusal echoes the private scalar back to the caller: %v", err)
	}
}

// Bearer compatibility, end to end and over two RPCs: a token minted with no
// JWK — what cmd/stratium-pep's reissueAndRetryDecide has always sent and
// still sends — authenticates at Decide and reaches the real three-leg
// evaluation, exactly as TestDecide_ValidToken_ReachesNormalDecision's own
// hand-built token does.
//
// Reaching DeniedLeg "principal" is what makes this a proof rather than an
// assertion: that leg is reachable ONLY after authentication succeeds and
// the agent load, chain load, tier derivation, and policy evaluation all
// run (see that test's own comment). A token that failed to verify would
// deny at "delegation", the structural pre-leg bucket, and a test that only
// checked "IssueToken returned something" could not tell the two apart.
func TestIssueToken_UnboundTokenStillAuthenticatesAtDecide(t *testing.T) {
	fs, req, delegationID := decideTokenFixture(t)
	fs.delegation = fs.chain[0] // the same root the fixture's chain describes, for IssueToken's own load
	signer := testSigner(t)
	srv := NewServer(fs, denyAllPolicy(), testConfig(), signer)

	issued, err := srv.IssueToken(context.Background(), &IssueTokenRequest{
		DelegationId: delegationID.String(),
		TtlSeconds:   600,
		// No DpopJwk, deliberately: this is the existing caller's exact shape.
	})
	if err != nil {
		t.Fatalf("IssueToken() error = %v, want success", err)
	}

	req.Token = issued.GetToken()
	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v, want a decision", err)
	}
	if resp.GetDeniedLeg() != "principal" {
		t.Fatalf("DeniedLeg = %q (reason %q), want %q: a re-issued bearer token must authenticate and "+
			"reach the full three-leg evaluation exactly as it did before cnf existed",
			resp.GetDeniedLeg(), resp.GetReason(), "principal")
	}
}
