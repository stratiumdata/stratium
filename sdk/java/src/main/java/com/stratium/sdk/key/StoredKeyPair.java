package com.stratium.sdk.key;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

public final class StoredKeyPair {
    private final KeyMetadata metadata;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    public StoredKeyPair(KeyMetadata metadata, PublicKey publicKey, PrivateKey privateKey) {
        this.metadata = Objects.requireNonNull(metadata, "metadata");
        this.publicKey = Objects.requireNonNull(publicKey, "publicKey");
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
    }

    public KeyMetadata getMetadata() {
        return metadata;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}
