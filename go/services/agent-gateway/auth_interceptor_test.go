package agent_gateway

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeVerifier struct {
	identity string
	err      error
	called   bool
}

func (f *fakeVerifier) Verify(_ context.Context, _ string) (string, error) {
	f.called = true
	return f.identity, f.err
}

func TestIdentityContextRoundTrip(t *testing.T) {
	ctx := withIdentity(context.Background(), "alice")
	id, ok := identityFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, "alice", id)

	_, ok = identityFromContext(context.Background())
	assert.False(t, ok)

	_, ok = identityFromContext(withIdentity(context.Background(), ""))
	assert.False(t, ok, "empty identity must be treated as absent")
}

func TestInterceptorValidToken(t *testing.T) {
	fv := &fakeVerifier{identity: "alice"}
	var gotIdentity string
	handler := func(ctx context.Context, _ any) (any, error) {
		gotIdentity, _ = identityFromContext(ctx)
		return "ok", nil
	}
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer good.jwt.token"))

	resp, err := IdentityVerificationInterceptor(fv)(ctx, nil, &grpc.UnaryServerInfo{}, handler)
	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
	assert.Equal(t, "alice", gotIdentity)
	assert.True(t, fv.called)
}

func TestInterceptorInvalidTokenRejected(t *testing.T) {
	fv := &fakeVerifier{err: errors.New("bad signature")}
	handlerCalled := false
	handler := func(_ context.Context, _ any) (any, error) {
		handlerCalled = true
		return "ok", nil
	}
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer forged.jwt"))

	_, err := IdentityVerificationInterceptor(fv)(ctx, nil, &grpc.UnaryServerInfo{}, handler)
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.False(t, handlerCalled, "handler must not run for an invalid token")
}

func TestInterceptorNoTokenPassesThroughWithoutIdentity(t *testing.T) {
	fv := &fakeVerifier{identity: "unused"}
	var hadIdentity bool
	handler := func(ctx context.Context, _ any) (any, error) {
		_, hadIdentity = identityFromContext(ctx)
		return "ok", nil
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs())

	resp, err := IdentityVerificationInterceptor(fv)(ctx, nil, &grpc.UnaryServerInfo{}, handler)
	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
	assert.False(t, hadIdentity)
	assert.False(t, fv.called, "verifier must not be called without a bearer")
}

func TestInterceptorIgnoresXUserID(t *testing.T) {
	fv := &fakeVerifier{}
	var hadIdentity bool
	handler := func(ctx context.Context, _ any) (any, error) {
		_, hadIdentity = identityFromContext(ctx)
		return "ok", nil
	}
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("x-user-id", "admin"))

	_, err := IdentityVerificationInterceptor(fv)(ctx, nil, &grpc.UnaryServerInfo{}, handler)
	require.NoError(t, err)
	assert.False(t, hadIdentity, "x-user-id must NOT establish identity")
	assert.False(t, fv.called)
}

func TestExtractUserIDFromContext(t *testing.T) {
	id, err := extractUserID(withIdentity(context.Background(), "bob"))
	require.NoError(t, err)
	assert.Equal(t, "bob", id)

	_, err = extractUserID(context.Background())
	require.Error(t, err)
}
