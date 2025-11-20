package key_manager

import (
	"context"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	"stratium/pkg/security/encryption"
)

// newTestKeyManagerServer creates a key manager server backed by in-memory stores.
func newTestKeyManagerServer(t testing.TB, alg encryption.Algorithm) *Server {
	t.Helper()

	keyStore := NewInMemoryKeyStore()
	clientKeyStore := NewInMemoryClientKeyStore()
	providerFactory := NewDefaultProviderFactory(alg)
	for _, providerType := range providerFactory.GetAvailableProviders() {
		provider, err := providerFactory.GetProvider(providerType)
		if err != nil {
			continue
		}
		if softwareProvider, ok := provider.(*SoftwareKeyProvider); ok {
			softwareProvider.SetKeyStore(keyStore)
		}
	}

	server := &Server{
		keyStore:        keyStore,
		clientKeyStore:  clientKeyStore,
		providerFactory: providerFactory,
		rotationManager: &testRotationManager{keyStore: keyStore},
		dekService:      NewDEKUnwrappingService(keyStore, providerFactory, clientKeyStore),
		integrityMgr:    NewKeyIntegrityManager(),
	}

	return server
}

// testRotationManager simulates rotation operations for tests.
type testRotationManager struct {
	keyStore KeyStore
}

func (n *testRotationManager) ScheduleRotation(keyID string, policy RotationPolicy, interval time.Duration) error {
	return nil
}

func (n *testRotationManager) CancelRotation(keyID string) error {
	return nil
}

func (n *testRotationManager) CheckRotationNeeded(key *Key) bool {
	return false
}

func (n *testRotationManager) PerformRotation(ctx context.Context, keyID string) (*RotateKeyResponse, error) {
	if n.keyStore == nil {
		return nil, fmt.Errorf("key store unavailable")
	}
	key, err := n.keyStore.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	now := timestamppb.Now()
	key.LastRotated = now
	return &RotateKeyResponse{
		OldKey:    key,
		NewKey:    key,
		Timestamp: now,
	}, nil
}
