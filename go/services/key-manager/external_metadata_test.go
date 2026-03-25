package key_manager

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnsureMetadata_NilMap(t *testing.T) {
	result := ensureMetadata(nil)
	assert.NotNil(t, result)
	assert.Empty(t, result)
}

func TestEnsureMetadata_ExistingMap(t *testing.T) {
	existing := map[string]string{"key": "value"}
	result := ensureMetadata(existing)
	assert.Equal(t, existing, result)
}

func TestApplyExternalMetadata_FullDescriptor(t *testing.T) {
	loadedAt := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	desc := externalMetadataDescriptor{
		SourceName:       "test-source",
		ManifestPath:     "/path/to/manifest",
		LoaderType:       "file",
		PrivateKeySource: "local",
		LoadedAt:         loadedAt,
	}
	meta := map[string]string{}
	result := applyExternalMetadata(meta, desc)

	assert.Equal(t, "true", result[metadataExternalManaged])
	assert.Equal(t, "test-source", result[metadataExternalSource])
	assert.Equal(t, "/path/to/manifest", result[metadataExternalManifestPath])
	assert.Equal(t, "file", result[metadataExternalLoaderType])
	assert.Equal(t, "local", result[metadataExternalPrivateKey])
	assert.Equal(t, loadedAt.UTC().Format(time.RFC3339), result[metadataExternalLoadedAt])
}

func TestApplyExternalMetadata_NilMeta(t *testing.T) {
	desc := externalMetadataDescriptor{
		SourceName: "test-source",
	}
	result := applyExternalMetadata(nil, desc)

	assert.NotNil(t, result)
	assert.Equal(t, "true", result[metadataExternalManaged])
	assert.Equal(t, "test-source", result[metadataExternalSource])
}

func TestApplyExternalMetadata_EmptyDescriptor(t *testing.T) {
	desc := externalMetadataDescriptor{}
	meta := map[string]string{}
	result := applyExternalMetadata(meta, desc)

	// Only managed should be set (always set to true)
	assert.Equal(t, "true", result[metadataExternalManaged])
	// Optional fields should not be set when empty
	_, hasSource := result[metadataExternalSource]
	assert.False(t, hasSource)
	_, hasManifest := result[metadataExternalManifestPath]
	assert.False(t, hasManifest)
	_, hasLoaderType := result[metadataExternalLoaderType]
	assert.False(t, hasLoaderType)
}

func TestHydrateKeyFromMetadata_NilKey(t *testing.T) {
	// Should not panic
	hydrateKeyFromMetadata(nil)
}

func TestHydrateKeyFromMetadata_NilMetadata(t *testing.T) {
	key := &Key{KeyId: "test-key"}
	// Should not panic
	hydrateKeyFromMetadata(key)
	assert.False(t, key.ExternallyManaged)
}

func TestHydrateKeyFromMetadata_ExternallyManaged(t *testing.T) {
	key := &Key{
		KeyId: "test-key",
		Metadata: map[string]string{
			metadataExternalManaged: "true",
			metadataExternalSource:  "vault",
		},
	}
	hydrateKeyFromMetadata(key)
	assert.True(t, key.ExternallyManaged)
	assert.Equal(t, "vault", key.ExternalSource)
}

func TestHydrateKeyFromMetadata_NotExternallyManaged(t *testing.T) {
	key := &Key{
		KeyId: "test-key",
		Metadata: map[string]string{
			metadataExternalManaged: "false",
		},
	}
	hydrateKeyFromMetadata(key)
	assert.False(t, key.ExternallyManaged)
}

func TestHydrateKeyFromMetadata_AllFields(t *testing.T) {
	loadedAt := time.Date(2024, 3, 10, 8, 0, 0, 0, time.UTC)
	key := &Key{
		KeyId: "test-key",
		Metadata: map[string]string{
			metadataExternalManaged:      "true",
			metadataExternalSource:       "aws-kms",
			metadataExternalManifestPath: "/keys/manifest.json",
			metadataExternalPrivateKey:   "hsm",
			metadataExternalLoadedAt:     loadedAt.UTC().Format(time.RFC3339),
		},
	}
	hydrateKeyFromMetadata(key)

	assert.True(t, key.ExternallyManaged)
	assert.Equal(t, "aws-kms", key.ExternalSource)
	assert.Equal(t, "/keys/manifest.json", key.ExternalManifestPath)
	assert.Equal(t, "hsm", key.PrivateKeySource)
	require.NotNil(t, key.ExternalLoadedAt)
	assert.Equal(t, loadedAt.Unix(), key.ExternalLoadedAt.AsTime().Unix())
}

func TestHydrateKeyFromMetadata_InvalidLoadedAt(t *testing.T) {
	key := &Key{
		KeyId: "test-key",
		Metadata: map[string]string{
			metadataExternalLoadedAt: "not-a-valid-timestamp",
		},
	}
	// Should not panic and should leave ExternalLoadedAt nil
	hydrateKeyFromMetadata(key)
	assert.Nil(t, key.ExternalLoadedAt)
}

func TestHydrateKeyPairFromMetadata_NilKeyPair(t *testing.T) {
	// Should not panic
	hydrateKeyPairFromMetadata(nil)
}

func TestHydrateKeyPairFromMetadata_NilMetadata(t *testing.T) {
	kp := &KeyPair{KeyID: "test-keypair"}
	// Should not panic
	hydrateKeyPairFromMetadata(kp)
	assert.False(t, kp.ExternallyManaged)
}

func TestHydrateKeyPairFromMetadata_ExternallyManaged(t *testing.T) {
	kp := &KeyPair{
		KeyID: "test-keypair",
		Metadata: map[string]string{
			metadataExternalManaged: "true",
			metadataExternalSource:  "gcp-kms",
		},
	}
	hydrateKeyPairFromMetadata(kp)
	assert.True(t, kp.ExternallyManaged)
	assert.Equal(t, "gcp-kms", kp.ExternalSource)
}

func TestHydrateKeyPairFromMetadata_AllFields(t *testing.T) {
	loadedAt := time.Date(2024, 5, 20, 14, 30, 0, 0, time.UTC)
	kp := &KeyPair{
		KeyID: "test-keypair",
		Metadata: map[string]string{
			metadataExternalManaged:      "true",
			metadataExternalSource:       "azure-keyvault",
			metadataExternalManifestPath: "/manifests/key.yaml",
			metadataExternalPrivateKey:   "pkcs11",
			metadataExternalLoaderType:   "remote",
			metadataExternalLoadedAt:     loadedAt.UTC().Format(time.RFC3339),
		},
	}
	hydrateKeyPairFromMetadata(kp)

	assert.True(t, kp.ExternallyManaged)
	assert.Equal(t, "azure-keyvault", kp.ExternalSource)
	assert.Equal(t, "/manifests/key.yaml", kp.ExternalManifestPath)
	assert.Equal(t, "pkcs11", kp.PrivateKeySource)
	assert.Equal(t, "remote", kp.ExternalLoaderType)
	require.NotNil(t, kp.ExternalLoadedAt)
	assert.Equal(t, loadedAt.Unix(), kp.ExternalLoadedAt.Unix())
}

func TestHydrateKeyPairFromMetadata_InvalidLoadedAt(t *testing.T) {
	kp := &KeyPair{
		KeyID: "test-keypair",
		Metadata: map[string]string{
			metadataExternalLoadedAt: "not-valid",
		},
	}
	// Should not panic and should leave ExternalLoadedAt nil
	hydrateKeyPairFromMetadata(kp)
	assert.Nil(t, kp.ExternalLoadedAt)
}

func TestApplyAndHydrateKey_RoundTrip(t *testing.T) {
	loadedAt := time.Date(2024, 6, 1, 10, 0, 0, 0, time.UTC)
	desc := externalMetadataDescriptor{
		SourceName:       "my-source",
		ManifestPath:     "/manifests/key.json",
		PrivateKeySource: "vault",
		LoaderType:       "http",
		LoadedAt:         loadedAt,
	}
	meta := applyExternalMetadata(nil, desc)

	key := &Key{
		KeyId:    "roundtrip-key",
		Metadata: meta,
	}
	hydrateKeyFromMetadata(key)

	assert.True(t, key.ExternallyManaged)
	assert.Equal(t, "my-source", key.ExternalSource)
	assert.Equal(t, "/manifests/key.json", key.ExternalManifestPath)
	assert.Equal(t, "vault", key.PrivateKeySource)
}

func TestApplyAndHydrateKeyPair_RoundTrip(t *testing.T) {
	loadedAt := time.Date(2024, 7, 4, 12, 0, 0, 0, time.UTC)
	desc := externalMetadataDescriptor{
		SourceName:       "kp-source",
		ManifestPath:     "/manifests/kp.json",
		PrivateKeySource: "tpm",
		LoaderType:       "local",
		LoadedAt:         loadedAt,
	}
	meta := applyExternalMetadata(nil, desc)

	kp := &KeyPair{
		KeyID:    "roundtrip-keypair",
		Metadata: meta,
	}
	hydrateKeyPairFromMetadata(kp)

	assert.True(t, kp.ExternallyManaged)
	assert.Equal(t, "kp-source", kp.ExternalSource)
	assert.Equal(t, "/manifests/kp.json", kp.ExternalManifestPath)
	assert.Equal(t, "tpm", kp.PrivateKeySource)
	assert.Equal(t, "local", kp.ExternalLoaderType)
	require.NotNil(t, kp.ExternalLoadedAt)
	assert.Equal(t, loadedAt.Unix(), kp.ExternalLoadedAt.Unix())
}
