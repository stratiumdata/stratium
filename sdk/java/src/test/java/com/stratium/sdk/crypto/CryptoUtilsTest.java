package com.stratium.sdk.crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CryptoUtilsTest {

    @Test
    void roundTripEncryptDecrypt() {
        byte[] dek = CryptoUtils.generateDek();
        byte[] iv = CryptoUtils.generateIv();
        byte[] plaintext = "hello stratium".getBytes(StandardCharsets.UTF_8);

        var result = CryptoUtils.encryptPayload(plaintext, dek, iv);
        byte[] decrypted = CryptoUtils.decryptPayload(result.ciphertext(), dek, iv);

        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void segmentedDecryptMatchesPlaintext() throws Exception {
        byte[] dek = CryptoUtils.generateDek();
        byte[] baseNonce = CryptoUtils.generateIv();
        byte[][] chunks = {
                "alpha".getBytes(StandardCharsets.UTF_8),
                "beta".getBytes(StandardCharsets.UTF_8),
                "gamma".getBytes(StandardCharsets.UTF_8)
        };

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(dek, "AES");
        MessageDigest chunkHasher = MessageDigest.getInstance("SHA-256");
        ByteArrayOutputStream payloadBuffer = new ByteArrayOutputStream();
        List<com.stratium.sdk.ztdf.IntegritySegment> segments = new ArrayList<>();
        MessageDigest rootHasher = MessageDigest.getInstance("SHA-256");

        for (int i = 0; i < chunks.length; i++) {
            byte[] nonce = deriveNonce(baseNonce, i);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
            byte[] cipherChunk = cipher.doFinal(chunks[i]);
            payloadBuffer.write(cipherChunk);
            rootHasher.update(cipherChunk);
            byte[] hash = chunkHasher.digest(cipherChunk);
            segments.add(new com.stratium.sdk.ztdf.IntegritySegment(
                    Base64.getEncoder().encodeToString(hash),
                    chunks[i].length,
                    cipherChunk.length
            ));
            chunkHasher.reset();
        }

        byte[] expectedRoot = rootHasher.digest();
        byte[] decrypted = CryptoUtils.decryptSegmentedPayload(
                payloadBuffer.toByteArray(),
                dek,
                baseNonce,
                segments,
                expectedRoot
        );

        ByteArrayOutputStream concatenated = new ByteArrayOutputStream();
        for (byte[] chunk : chunks) {
            concatenated.writeBytes(chunk);
        }

        assertThat(decrypted).isEqualTo(concatenated.toByteArray());
    }

    @Test
    void policyBindingRoundTrip() {
        byte[] dek = CryptoUtils.generateDek();
        String policyBase64 = Base64.getEncoder().encodeToString("policy".getBytes(StandardCharsets.UTF_8));
        byte[] binding = CryptoUtils.calculatePolicyBinding(dek, policyBase64);
        boolean valid = CryptoUtils.verifyPolicyBinding(
                dek,
                policyBase64,
                Base64.getEncoder().encodeToString(binding)
        );
        assertThat(valid).isTrue();
    }

    @Test
    void decryptDekRoundTrip() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair clientKeyPair = generator.generateKeyPair();

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, clientKeyPair.getPublic());

        byte[] dek = CryptoUtils.generateDek();
        byte[] ciphertext = cipher.doFinal(dek);

        byte[] decrypted = CryptoUtils.decryptDek(ciphertext, clientKeyPair.getPrivate());
        assertThat(decrypted).isEqualTo(dek);
    }

    private static byte[] deriveNonce(byte[] base, int index) {
        byte[] nonce = base.clone();
        ByteBuffer buffer = ByteBuffer.wrap(nonce).order(ByteOrder.BIG_ENDIAN);
        buffer.position(nonce.length - 4);
        buffer.putInt(index);
        return nonce;
    }
}
