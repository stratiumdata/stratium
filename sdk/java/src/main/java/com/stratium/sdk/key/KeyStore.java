package com.stratium.sdk.key;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;

public interface KeyStore {
    void saveKeyPair(KeyMetadata metadata, PublicKey publicKey, PrivateKey privateKey);
    Optional<StoredKeyPair> getLatestKey();
    void delete(String keyId);
}
