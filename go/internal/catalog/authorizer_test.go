// go/internal/catalog/authorizer_test.go
package catalog

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeAuthorizer struct {
	got      AuthRequest
	decision AuthDecision
	err      error
}

func (f *fakeAuthorizer) Authorize(_ context.Context, req AuthRequest) (AuthDecision, error) {
	f.got = req
	return f.decision, f.err
}

func TestAuthorizerContract(t *testing.T) {
	f := &fakeAuthorizer{decision: AuthDecision{Authorized: true}}
	var a Authorizer = f // compile-time check the fake satisfies the interface

	dec, err := a.Authorize(context.Background(), AuthRequest{
		ToolName:   "github_read_file",
		Action:     "read",
		ActionTier: 1,
	})
	require.NoError(t, err)
	assert.True(t, dec.Authorized)
	assert.Equal(t, "github_read_file", f.got.ToolName)
}
