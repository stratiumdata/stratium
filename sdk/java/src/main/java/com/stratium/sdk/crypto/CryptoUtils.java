package com.stratium.sdk.crypto;

import com.stratium.sdk.ztdf.IntegritySegment;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Cryptographic helpers mirroring the browser/Go SDK behavior.
 */
public final class CryptoUtils {
    private static final int AES_KEY_SIZE_BYTES = 32; // AES-256
    private static final int AES_GCM_IV_BYTES = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private CryptoUtils() {
    }

    public static byte[] generateDek() {
        byte[] dek = new byte[AES_KEY_SIZE_BYTES];
        SECURE_RANDOM.nextBytes(dek);
        return dek;
    }

    public static byte[] generateIv() {
        byte[] iv = new byte[AES_GCM_IV_BYTES];
        SECURE_RANDOM.nextBytes(iv);
        return iv;
    }

    public static PayloadEncryptionResult encryptPayload(byte[] plaintext, byte[] dek, byte[] iv) {
        try {
            byte[] effectiveIv = iv != null ? iv : generateIv();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec key = new SecretKeySpec(dek, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, effectiveIv));
            byte[] ciphertext = cipher.doFinal(plaintext);
            return new PayloadEncryptionResult(ciphertext, effectiveIv);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("encrypt", "Failed to encrypt payload", e);
        }
    }

    public static byte[] decryptPayload(byte[] ciphertext, byte[] dek, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec key = new SecretKeySpec(dek, "AES");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("decrypt", "Failed to decrypt payload", e);
        }
    }

    public static byte[] decryptSegmentedPayload(
            byte[] payload,
            byte[] dek,
            byte[] baseNonce,
            List<IntegritySegment> segments,
            byte[] expectedRootHash
    ) {
        if (segments == null || segments.isEmpty()) {
            throw new CryptoException("decrypt", "Missing integrity segments for segmented payload");
        }
        ByteBuffer ciphertextBuffer = ByteBuffer.wrap(payload);
        List<byte[]> chunks = new ArrayList<>(segments.size());
        MessageDigest hasher = newDigest();

        for (int i = 0; i < segments.size(); i++) {
            IntegritySegment segment = segments.get(i);
            int encryptedSize = segment.getEncryptedSegmentSize();
            if (encryptedSize <= 0 || encryptedSize > ciphertextBuffer.remaining()) {
                throw new CryptoException("decrypt", "Encrypted payload length mismatch for chunk " + i);
            }
            byte[] chunkCipher = new byte[encryptedSize];
            ciphertextBuffer.get(chunkCipher);

            if (segment.getHashBase64() != null && !segment.getHashBase64().isEmpty()) {
                byte[] expectedHash = Base64.getDecoder().decode(segment.getHashBase64());
                byte[] actualHash = digest(chunkCipher);
                if (!MessageDigest.isEqual(actualHash, expectedHash)) {
                    throw new CryptoException("decrypt", "Segment hash mismatch for chunk " + i);
                }
            }

            byte[] nonce = deriveChunkNonce(baseNonce, i);
            byte[] chunkPlain = decryptPayload(chunkCipher, dek, nonce);
            chunks.add(chunkPlain);
            hasher.update(chunkCipher);
        }

        if (ciphertextBuffer.hasRemaining()) {
            throw new CryptoException("decrypt", "Encrypted payload contains extra data beyond declared segments");
        }

        if (expectedRootHash != null && expectedRootHash.length > 0) {
            byte[] actualRoot = hasher.digest();
            if (!MessageDigest.isEqual(actualRoot, expectedRootHash)) {
                throw new CryptoException("decrypt", "Payload integrity verification failed");
            }
        }

        return concatChunks(chunks);
    }

    public static byte[] calculatePayloadHash(byte[] payload) {
        return digest(payload);
    }

    public static boolean verifyPayloadHash(byte[] payload, byte[] expected) {
        return MessageDigest.isEqual(calculatePayloadHash(payload), expected);
    }

    public static byte[] calculatePolicyBinding(byte[] dek, String policyBase64) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(dek, "HmacSHA256"));
            mac.update(policyBase64.getBytes());
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("hmac", "Failed to calculate policy binding", e);
        }
    }

    public static byte[] decryptDek(byte[] encryptedDek, PrivateKey privateKey) {
        if (!(privateKey instanceof RSAPrivateKey rsaPrivateKey)) {
            throw new CryptoException("decrypt", "Client key must be RSA for DEK decryption", null);
        }
        System.err.println("[CryptoUtils] private key algo=" + rsaPrivateKey.getAlgorithm()
                + ", size=" + rsaPrivateKey.getModulus().bitLength());
        String cipherPreview = Base64.getEncoder().encodeToString(
                Arrays.copyOf(encryptedDek, Math.min(encryptedDek.length, 48))
        );
        System.err.println("[CryptoUtils] ciphertext preview=" + cipherPreview);
        GeneralSecurityException lastError = null;
        DecryptAttempt attempt = tryOaep(rsaPrivateKey, encryptedDek, "SHA-256", "SHA-256");
        if (attempt.result() != null) {
            return attempt.result();
        }
        lastError = attempt.error();
        attempt = tryOaep(rsaPrivateKey, encryptedDek, "SHA-256", "SHA-1");
        if (attempt.result() != null) {
            return attempt.result();
        }
        lastError = attempt.error();
        attempt = tryOaep(rsaPrivateKey, encryptedDek, "SHA-1", "SHA-1");
        if (attempt.result() != null) {
            return attempt.result();
        }
        lastError = attempt.error();
        try {
            System.err.println("[CryptoUtils] Attempting RSA decrypt using RSA/ECB/PKCS1Padding");
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
            return cipher.doFinal(encryptedDek);
        } catch (GeneralSecurityException e) {
            System.err.println("[CryptoUtils] RSA/ECB/PKCS1Padding failed: " + e.getMessage());
            lastError = e;
        }
        throw new CryptoException("decrypt", "Failed to decrypt DEK", lastError);
    }

    private record DecryptAttempt(byte[] result, GeneralSecurityException error) {}

    private static DecryptAttempt tryOaep(RSAPrivateKey privateKey, byte[] ciphertext,
                                          String digest, String mgfDigest) {
        try {
            System.err.println("[CryptoUtils] Attempting RSA decrypt using OAEP digest=" + digest + ", mgf=" + mgfDigest);
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            OAEPParameterSpec spec = new OAEPParameterSpec(
                    digest,
                    "MGF1",
                    new MGF1ParameterSpec(mgfDigest),
                    PSource.PSpecified.DEFAULT
            );
            cipher.init(Cipher.DECRYPT_MODE, privateKey, spec);
            return new DecryptAttempt(cipher.doFinal(ciphertext), null);
        } catch (GeneralSecurityException e) {
            System.err.println("[CryptoUtils] OAEP digest=" + digest + ", mgf=" + mgfDigest + " failed: " + e.getMessage());
            return new DecryptAttempt(null, e);
        }
    }

    public static boolean verifyPolicyBinding(byte[] dek, String policyBase64, String expectedBase64) {
        byte[] actual = calculatePolicyBinding(dek, policyBase64);
        byte[] expected = Base64.getDecoder().decode(expectedBase64);
        return MessageDigest.isEqual(actual, expected);
    }

    private static byte[] deriveChunkNonce(byte[] baseNonce, int chunkIndex) {
        byte[] nonce = baseNonce.clone();
        if (nonce.length < 4) {
            return nonce;
        }
        ByteBuffer buffer = ByteBuffer.wrap(nonce).order(ByteOrder.BIG_ENDIAN);
        buffer.position(nonce.length - 4);
        buffer.putInt(chunkIndex);
        return nonce;
    }

    private static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static byte[] digest(byte[] data) {
        return newDigest().digest(data);
    }

    private static byte[] concatChunks(List<byte[]> chunks) {
        int total = chunks.stream().mapToInt(chunk -> chunk.length).sum();
        byte[] result = new byte[total];
        int offset = 0;
        for (byte[] chunk : chunks) {
            System.arraycopy(chunk, 0, result, offset, chunk.length);
            offset += chunk.length;
        }
        return result;
    }

    public record PayloadEncryptionResult(byte[] ciphertext, byte[] iv) {}
}
