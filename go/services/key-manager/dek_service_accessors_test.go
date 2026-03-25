package key_manager

import (
	"context"
	"testing"

	"stratium/pkg/security/encryption"

	"github.com/stretchr/testify/require"
)

func TestDEKUnwrappingService_SetAuditLogger_Nil(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)
	dekSvc := server.dekService

	// Setting nil logger should not panic
	dekSvc.SetAuditLogger(nil)
}

func TestDEKUnwrappingService_RegisterClientPublicKey_ValidRSAKey(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)
	dekSvc := server.dekService

	ctx := context.Background()

	// Generate an RSA key pair to register
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	keyPair, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_RSA_2048, "test-key", nil)
	require.NoError(t, err)

	// Register the public key
	err = dekSvc.RegisterClientPublicKey(ctx, "test-subject", keyPair.PublicKeyPEM)
	require.NoError(t, err)
}

func TestDefaultAuditLogger_LogDEKAccess_Granted(t *testing.T) {
	logger := &DefaultAuditLogger{}
	ctx := context.Background()

	event := DEKAccessEvent{
		Subject:       "user@example.com",
		Resource:      "document-123",
		KeyID:         "key-abc",
		AccessGranted: true,
		Reason:        "Policy allows access",
		AppliedRules:  []string{"rule-1", "rule-2"},
		ClientIP:      "192.168.1.1",
	}

	// Should not panic
	logger.LogDEKAccess(ctx, event)
}

func TestDefaultAuditLogger_LogDEKAccess_Denied(t *testing.T) {
	logger := &DefaultAuditLogger{}
	ctx := context.Background()

	event := DEKAccessEvent{
		Subject:       "attacker@evil.com",
		Resource:      "secret-document",
		KeyID:         "key-xyz",
		AccessGranted: false,
		Reason:        "Insufficient permissions",
		AppliedRules:  []string{"deny-rule"},
		ClientIP:      "10.0.0.1",
	}

	// Should not panic
	logger.LogDEKAccess(ctx, event)
}

func TestDefaultAuditLogger_LogSecurityEvent_AllFields(t *testing.T) {
	auditLogger := &DefaultAuditLogger{}
	ctx := context.Background()

	events := []SecurityEvent{
		{
			EventType:   "UNAUTHORIZED_ACCESS",
			KeyID:       "key-1",
			Subject:     "user1",
			Severity:    "HIGH",
			Description: "Unauthorized key access attempt",
		},
		{
			EventType:   "KEY_ROTATION",
			KeyID:       "key-2",
			Subject:     "system",
			Severity:    "INFO",
			Description: "Scheduled key rotation completed",
		},
		{
			EventType:   "KEY_REVOCATION",
			KeyID:       "key-3",
			Subject:     "admin",
			Severity:    "MEDIUM",
			Description: "Key revoked per policy",
		},
	}

	for _, event := range events {
		// Should not panic
		auditLogger.LogSecurityEvent(ctx, event)
	}
}

func TestDEKUnwrappingService_SetClientKeyStore_ThenRegisterKey(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)
	dekSvc := server.dekService

	// Replace the client key store
	newStore := NewInMemoryClientKeyStore()
	dekSvc.SetClientKeyStore(newStore)

	ctx := context.Background()

	// Generate a key pair for testing
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	keyPair, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_RSA_2048, "test-key", nil)
	require.NoError(t, err)

	// Register the public key after setting a new client key store
	err = dekSvc.RegisterClientPublicKey(ctx, "subject-after-store-swap", keyPair.PublicKeyPEM)
	require.NoError(t, err)
}
