package com.stratium.sdk.key;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Comparator;
import java.util.Optional;

public final class FileKeyStore implements KeyStore {
    private final Path root;

    public FileKeyStore(Path root) {
        this.root = root;
    }

    @Override
    public void saveKeyPair(KeyMetadata metadata, PublicKey publicKey, PrivateKey privateKey) {
        try {
            Path dir = root.resolve(metadata.getKeyId());
            Files.createDirectories(dir);
            Files.writeString(dir.resolve("metadata.txt"), serializeMetadata(metadata));
            Files.writeString(dir.resolve("public.pem"), Base64.getEncoder().encodeToString(publicKey.getEncoded()));
            Files.writeString(dir.resolve("private.pem"), Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        } catch (IOException e) {
            throw new RuntimeException("Failed to persist key pair", e);
        }
    }

    @Override
    public Optional<StoredKeyPair> getLatestKey() {
        try {
            if (!Files.exists(root)) {
                return Optional.empty();
            }
            return Files.list(root)
                    .filter(Files::isDirectory)
                    .map(this::loadKeyPair)
                    .filter(Optional::isPresent)
                    .map(Optional::get)
                    .filter(k -> !k.getMetadata().isExpired())
                    .max(Comparator.comparing(k -> k.getMetadata().getCreatedAt()));
        } catch (IOException e) {
            throw new RuntimeException("Failed to enumerate keys", e);
        }
    }

    @Override
    public void delete(String keyId) {
        try {
            Path dir = root.resolve(keyId);
            if (Files.exists(dir)) {
                Files.walk(dir)
                        .sorted(Comparator.reverseOrder())
                        .forEach(path -> {
                            try {
                                Files.delete(path);
                            } catch (IOException e) {
                                throw new RuntimeException(e);
                            }
                        });
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to delete key", e);
        }
    }

    private Optional<StoredKeyPair> loadKeyPair(Path dir) {
        try {
            if (!Files.exists(dir.resolve("metadata.txt"))) {
                return Optional.empty();
            }
            KeyMetadata metadata = parseMetadata(Files.readString(dir.resolve("metadata.txt")));
            byte[] publicBytes = Base64.getDecoder().decode(Files.readString(dir.resolve("public.pem")));
            byte[] privateBytes = Base64.getDecoder().decode(Files.readString(dir.resolve("private.pem")));
            PrivateKey privateKey = generatePrivateKey(privateBytes);
            PublicKey publicKey = generatePublicKey(publicBytes);
            if (privateKey == null || publicKey == null) {
                return Optional.empty();
            }
            return Optional.of(new StoredKeyPair(metadata, publicKey, privateKey));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    private PrivateKey generatePrivateKey(byte[] encoded) {
        for (String algorithm : new String[]{"RSA", "EC"}) {
            try {
                KeyFactory factory = KeyFactory.getInstance(algorithm);
                return factory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
            } catch (NoSuchAlgorithmException | InvalidKeySpecException ignored) {
                // Try next algorithm
            }
        }
        return null;
    }

    private PublicKey generatePublicKey(byte[] encoded) {
        for (String algorithm : new String[]{"RSA", "EC"}) {
            try {
                KeyFactory factory = KeyFactory.getInstance(algorithm);
                return factory.generatePublic(new X509EncodedKeySpec(encoded));
            } catch (NoSuchAlgorithmException | InvalidKeySpecException ignored) {
                // Try next algorithm
            }
        }
        return null;
    }

    private static String serializeMetadata(KeyMetadata metadata) {
        return metadata.getKeyId() + "\n" + metadata.getCreatedAt().toEpochMilli() + "\n" + metadata.getExpiresAt().toEpochMilli();
    }

    private static KeyMetadata parseMetadata(String content) {
        String[] parts = content.split("\n");
        return new KeyMetadata(
                parts[0],
                Instant.ofEpochMilli(Long.parseLong(parts[1])),
                Instant.ofEpochMilli(Long.parseLong(parts[2]))
        );
    }
}
