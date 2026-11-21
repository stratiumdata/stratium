package pdpgrpc

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCreateDelegation_TTLAboveTheMaximumIsRefused(t *testing.T) {
	cfg := testConfig()
	cfg.MaxDelegationTTL = time.Hour

	for _, tc := range []struct {
		ttl  int64
		want codes.Code
	}{
		{3600, codes.OK},
		{3601, codes.InvalidArgument},
		{math.MaxInt64, codes.InvalidArgument},
	} {
		fs, req, _ := wellFormedDelegationFixture()
		req.TtlSeconds = tc.ttl
		srv := NewServer(fs, singleFakeLanguagePolicy(fakePolicyEngine{set: permissiveGrantSet()}), cfg, &fakeSigner{})

		before := time.Now()
		_, err := srv.CreateDelegation(context.Background(), req)
		if got := status.Code(err); got != tc.want {
			t.Errorf("ttl %d: code = %s (%v), want %s", tc.ttl, got, err, tc.want)
			continue
		}
		if err != nil {
			if len(fs.created) != 0 {
				t.Errorf("ttl %d: refused, but a delegation was written", tc.ttl)
			}
			continue
		}
		if len(fs.created) != 1 {
			t.Fatalf("ttl %d: %d delegations written, want 1", tc.ttl, len(fs.created))
		}
		if exp := fs.created[0].ExpiresAt; exp.Before(before.Add(time.Hour)) || exp.After(time.Now().Add(time.Hour)) {
			t.Errorf("ttl %d: expires_at = %v, want one hour from now", tc.ttl, exp)
		}
	}
}

// With no maximum configured, a ttl_seconds too large for time.Duration must
// still produce a lifetime in the future, never one that wrapped negative.
func TestBoundedTTL_NeverOverflows(t *testing.T) {
	srv := NewServer(nil, denyAllPolicy(), testConfig(), &fakeSigner{})
	for _, seconds := range []int64{math.MaxInt64, math.MaxInt64 / int64(time.Second), 1 << 40} {
		if got := srv.boundedTTL(seconds); got != ttlHardCeiling {
			t.Errorf("boundedTTL(%d) = %v, want the hard ceiling %v", seconds, got, ttlHardCeiling)
		}
	}
	if got := srv.boundedTTL(90); got != 90*time.Second {
		t.Errorf("boundedTTL(90) = %v, want 1m30s", got)
	}
}

func TestIssueToken_EnormousTTLStillEndsAtTheDelegationExpiry(t *testing.T) {
	signer := testSigner(t)
	id := uuid.New()
	now := time.Now()
	d := activeDelegation(id, now)
	d.ExpiresAt = now.Add(5 * time.Minute)
	cfg := testConfig()
	cfg.MaxDelegationTTL = 24 * time.Hour
	srv := NewServer(&fakeStore{delegation: d}, denyAllPolicy(), cfg, signer)

	resp, err := srv.IssueToken(context.Background(), &IssueTokenRequest{
		DelegationId: id.String(),
		Token:        priorToken(t, signer, id, ""),
		TtlSeconds:   math.MaxInt64,
	})
	if err != nil {
		t.Fatalf("IssueToken() = %v, want success", err)
	}
	if got := resp.GetExpiresAt().AsTime(); !got.Equal(d.ExpiresAt) || !resp.GetClampedToDelegationExpiry() {
		t.Errorf("expires_at = %v clamped = %v, want %v and true", got, resp.GetClampedToDelegationExpiry(), d.ExpiresAt)
	}
}
