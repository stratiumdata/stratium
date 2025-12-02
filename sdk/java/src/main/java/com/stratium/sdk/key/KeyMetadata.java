package com.stratium.sdk.key;

import java.time.Instant;
import java.util.Objects;

public final class KeyMetadata {
    private final String keyId;
    private final Instant createdAt;
    private final Instant expiresAt;

    public KeyMetadata(String keyId, Instant createdAt, Instant expiresAt) {
        this.keyId = Objects.requireNonNull(keyId, "keyId");
        this.createdAt = Objects.requireNonNull(createdAt, "createdAt");
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
    }

    public String getKeyId() {
        return keyId;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
}
