package key_manager

import (
	"strconv"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	metadataExternalManaged      = "external.managed"
	metadataExternalSource       = "external.source"
	metadataExternalManifestPath = "external.manifest_path"
	metadataExternalPrivateKey   = "external.private_key_source"
	metadataExternalLoaderType   = "external.loader_type"
	metadataExternalLoadedAt     = "external.loaded_at"
)

type externalMetadataDescriptor struct {
	SourceName       string
	ManifestPath     string
	LoaderType       string
	PrivateKeySource string
	LoadedAt         time.Time
}

func ensureMetadata(meta map[string]string) map[string]string {
	if meta == nil {
		meta = make(map[string]string)
	}
	return meta
}

func applyExternalMetadata(meta map[string]string, desc externalMetadataDescriptor) map[string]string {
	meta = ensureMetadata(meta)
	meta[metadataExternalManaged] = strconv.FormatBool(true)
	if desc.SourceName != "" {
		meta[metadataExternalSource] = desc.SourceName
	}
	if desc.ManifestPath != "" {
		meta[metadataExternalManifestPath] = desc.ManifestPath
	}
	if desc.PrivateKeySource != "" {
		meta[metadataExternalPrivateKey] = desc.PrivateKeySource
	}
	if desc.LoaderType != "" {
		meta[metadataExternalLoaderType] = desc.LoaderType
	}
	if !desc.LoadedAt.IsZero() {
		meta[metadataExternalLoadedAt] = desc.LoadedAt.UTC().Format(time.RFC3339)
	}
	return meta
}

func hydrateKeyFromMetadata(key *Key) {
	if key == nil || key.Metadata == nil {
		return
	}

	if val, ok := key.Metadata[metadataExternalManaged]; ok && val == "true" {
		key.ExternallyManaged = true
	}
	if val, ok := key.Metadata[metadataExternalSource]; ok {
		key.ExternalSource = val
	}
	if val, ok := key.Metadata[metadataExternalManifestPath]; ok {
		key.ExternalManifestPath = val
	}
	if val, ok := key.Metadata[metadataExternalPrivateKey]; ok {
		key.PrivateKeySource = val
	}
	if val, ok := key.Metadata[metadataExternalLoadedAt]; ok {
		if ts, err := time.Parse(time.RFC3339, val); err == nil {
			key.ExternalLoadedAt = timestamppb.New(ts)
		}
	}
}

func hydrateKeyPairFromMetadata(keyPair *KeyPair) {
	if keyPair == nil || keyPair.Metadata == nil {
		return
	}

	if val, ok := keyPair.Metadata[metadataExternalManaged]; ok && val == "true" {
		keyPair.ExternallyManaged = true
	}
	if val, ok := keyPair.Metadata[metadataExternalSource]; ok {
		keyPair.ExternalSource = val
	}
	if val, ok := keyPair.Metadata[metadataExternalManifestPath]; ok {
		keyPair.ExternalManifestPath = val
	}
	if val, ok := keyPair.Metadata[metadataExternalPrivateKey]; ok {
		keyPair.PrivateKeySource = val
	}
	if val, ok := keyPair.Metadata[metadataExternalLoaderType]; ok {
		keyPair.ExternalLoaderType = val
	}
	if val, ok := keyPair.Metadata[metadataExternalLoadedAt]; ok {
		if ts, err := time.Parse(time.RFC3339, val); err == nil {
			keyPair.ExternalLoadedAt = &ts
		}
	}
}
