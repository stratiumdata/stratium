package com.stratium.sdk.client;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.stratium.sdk.crypto.CryptoUtils;
import com.stratium.sdk.crypto.CryptoUtils.PayloadEncryptionResult;
import com.stratium.sdk.crypto.PemUtils;
import com.stratium.sdk.key.KeyManagerClient;
import com.stratium.sdk.key.KeyMetadata;
import com.stratium.sdk.key.KeyStore;
import com.stratium.sdk.key.StoredKeyPair;
import com.stratium.sdk.ztdf.IntegritySegment;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * High-level facade providing wrap/unwrap flows mirroring the Go/JS SDKs.
 */
public final class StratiumClient {
    private static final ObjectMapper MANIFEST_MAPPER = new ObjectMapper()
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);
    private static final String POLICY_BINDING_ALG = "HS256";
    private final StratiumClientConfig config;
    private final KeyStore keyStore;
    private final TokenProvider tokenProvider;
    private final ManagedChannel keyAccessChannel;
    private final ManagedChannel keyManagerChannel;
    private final KeyAccessClient keyAccessClient;
    private final KeyManagerClient keyManagerClient;
    private StoredKeyPair currentKeyPair;

    public StratiumClient(StratiumClientConfig config, KeyStore keyStore, TokenProvider tokenProvider) {
        this.config = config;
        this.keyStore = keyStore;
        this.tokenProvider = tokenProvider;
        this.keyAccessChannel = buildChannel(config.getKeyAccessUri());
        this.keyManagerChannel = buildChannel(config.getKeyManagerUri());
        this.keyAccessClient = new KeyAccessClient(keyAccessChannel, tokenProvider);
        this.keyManagerClient = new KeyManagerClient(keyManagerChannel, tokenProvider);
    }

    public CompletableFuture<Void> initialize() {
        return CompletableFuture.runAsync(() -> {
            this.currentKeyPair = keyStore.getLatestKey().orElseGet(this::registerNewKeyPair);
        });
    }

    public WrapResult wrap(byte[] plaintext, WrapOptions options) {
        return wrapInternal(plaintext, options, true);
    }

    private WrapResult wrapInternal(byte[] plaintext, WrapOptions options, boolean allowReRegister) {
        ensureInitialized();
        WrapOptions effectiveOptions = options != null ? options : WrapOptions.builder().build();

        byte[] dek = CryptoUtils.generateDek();
        byte[] iv = CryptoUtils.generateIv();
        PayloadEncryptionResult encrypted = CryptoUtils.encryptPayload(plaintext, dek, iv);

        byte[] clientWrappedDek = wrapDekWithPrivateKey(dek, (RSAPrivateKey) currentKeyPair.getPrivateKey());

        KeyAccessClient.WrapDekResult wrapResult;
        try {
            wrapResult = keyAccessClient.wrapDek(
                    clientWrappedDek,
                    effectiveOptions.getResource(),
                    effectiveOptions.getAction(),
                    effectiveOptions.getContext(),
                    effectiveOptions.getPolicyBase64(),
                    currentKeyPair.getMetadata().getKeyId()
            );
        } catch (RuntimeException e) {
            throw new IllegalStateException("Failed to call Key Access Service", e);
        }

        if (!wrapResult.accessGranted()) {
            if (allowReRegister && wrapResult.accessReason() != null &&
                    wrapResult.accessReason().toLowerCase().contains("no active client keys")) {
                this.currentKeyPair = registerNewKeyPair();
                return wrapInternal(plaintext, options, false);
            }
            throw new IllegalStateException("Access denied by Key Access Service: " + wrapResult.accessReason());
        }

        String payloadHashBase64 = null;
        if (effectiveOptions.isIntegrityCheck()) {
            payloadHashBase64 = Base64.getEncoder().encodeToString(CryptoUtils.calculatePayloadHash(plaintext));
        }

        String policyBindingBase64 = null;
        if (effectiveOptions.getPolicyBase64() != null && !effectiveOptions.getPolicyBase64().isBlank()) {
            policyBindingBase64 = Base64.getEncoder().encodeToString(
                    CryptoUtils.calculatePolicyBinding(dek, effectiveOptions.getPolicyBase64())
            );
        }

        byte[] manifestBytes = buildManifestBytes(effectiveOptions, iv, wrapResult, payloadHashBase64, policyBindingBase64);
        byte[] ztdfBlob = packageZtdf(manifestBytes, encrypted.ciphertext());

        return new WrapResult(ztdfBlob, plaintext.length, encrypted.ciphertext().length);
    }

    public byte[] unwrap(byte[] ztdfBlob) {
        ensureInitialized();
        ZtdfFile ztdfFile = ZtdfParser.parse(ztdfBlob);
        ZtdfManifest manifest = ztdfFile.manifest();
        String resource = manifest.filename();
        if (resource == null || resource.isBlank()) {
            resource = "encrypted-file";
        }
        String action = "decrypt";
        Map<String, String> context = Map.of();

        ZtdfManifest.EncryptionInformationKeyAccessEntry keyAccess = manifest.encryptionInformation().keyAccess().get(0);
        KeyAccessClient.UnwrapDekResult unwrapResult = keyAccessClient.unwrapDek(
                Base64.getDecoder().decode(keyAccess.wrappedKey()),
                resource,
                keyAccess.kid(),
                action,
                context,
                manifest.encryptionInformation().policy(),
                currentKeyPair.getMetadata().getKeyId()
        );

        if (!unwrapResult.accessGranted()) {
            throw new IllegalStateException("Access denied by Key Access Service: " + unwrapResult.accessReason());
        }

        byte[] encryptedForSubject = unwrapResult.encryptedDekForSubject();
        String dekPreview = Base64.getEncoder().encodeToString(
                Arrays.copyOf(encryptedForSubject, Math.min(48, encryptedForSubject.length))
        );
        System.err.println("[StratiumClient] encrypted DEK for subject length=" + encryptedForSubject.length
                + ", clientKeyId=" + currentKeyPair.getMetadata().getKeyId()
                + ", preview=" + dekPreview);
        byte[] dek = CryptoUtils.decryptDek(encryptedForSubject, currentKeyPair.getPrivateKey());

        ZtdfManifest.PolicyBinding policyBinding = keyAccess.policyBinding();
        if (policyBinding != null && policyBinding.hash() != null && !policyBinding.hash().isBlank()
                && manifest.encryptionInformation().policy() != null) {
            boolean valid = CryptoUtils.verifyPolicyBinding(dek,
                    manifest.encryptionInformation().policy(),
                    policyBinding.hash());
            if (!valid) {
                throw new IllegalStateException("Policy binding verification failed");
            }
        }

        byte[] iv = Base64.getDecoder().decode(manifest.encryptionInformation().method().iv());
        boolean isSegmented = manifest.encryptionInformation().method().isStreamable()
                && manifest.encryptionInformation().integrityInformation() != null
                && manifest.encryptionInformation().integrityInformation().segments() != null
                && !manifest.encryptionInformation().integrityInformation().segments().isEmpty();

        byte[] plaintext;
        if (isSegmented) {
            List<IntegritySegment> segments = toIntegritySegments(manifest);
            byte[] rootHash = rootHash(manifest);
            plaintext = CryptoUtils.decryptSegmentedPayload(
                    ztdfFile.payload(), dek, iv, segments, rootHash
            );
        } else {
            plaintext = CryptoUtils.decryptPayload(ztdfFile.payload(), dek, iv);
            if (manifest.payloadHash() != null && !manifest.payloadHash().isBlank()) {
                byte[] expected = Base64.getDecoder().decode(manifest.payloadHash());
                if (!CryptoUtils.verifyPayloadHash(plaintext, expected)) {
                    throw new IllegalStateException("Payload integrity verification failed");
                }
            }
        }

        return plaintext;
    }

    private byte[] buildManifestBytes(WrapOptions options,
                                      byte[] iv,
                                      KeyAccessClient.WrapDekResult wrapResult,
                                      String payloadHashBase64,
                                      String policyBindingBase64) {
        try {
            Map<String, Object> manifest = new LinkedHashMap<>();
            manifest.put("filename", options.getFilename());
            manifest.put("contentType", options.getContentType());

            Map<String, Object> encryptionInfo = new LinkedHashMap<>();
            encryptionInfo.put("type", "split");

            Map<String, Object> keyAccessEntry = new LinkedHashMap<>();
            keyAccessEntry.put("type", "wrapped");
            keyAccessEntry.put("kid", wrapResult.keyId());
            keyAccessEntry.put("wrappedKey", Base64.getEncoder().encodeToString(wrapResult.wrappedDek()));
            if (policyBindingBase64 != null && !policyBindingBase64.isBlank()) {
                Map<String, Object> policyBinding = new LinkedHashMap<>();
                policyBinding.put("alg", POLICY_BINDING_ALG);
                policyBinding.put("hash", policyBindingBase64);
                keyAccessEntry.put("policyBinding", policyBinding);
            }
            keyAccessEntry.put("url", config.getKeyAccessUri().toString());
            keyAccessEntry.put("protocol", "kas");

            encryptionInfo.put("keyAccess", List.of(keyAccessEntry));

            Map<String, Object> method = new LinkedHashMap<>();
            method.put("algorithm", "AES-256-GCM");
            method.put("iv", Base64.getEncoder().encodeToString(iv));
            method.put("isStreamable", false);
            encryptionInfo.put("method", method);

            if (options.getPolicyBase64() != null && !options.getPolicyBase64().isBlank()) {
                encryptionInfo.put("policy", options.getPolicyBase64());
            }

            manifest.put("encryptionInformation", encryptionInfo);
            if (payloadHashBase64 != null) {
                manifest.put("payloadHash", payloadHashBase64);
            }

            return MANIFEST_MAPPER.writeValueAsBytes(manifest);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to serialize manifest", e);
        }
    }

    private static List<IntegritySegment> toIntegritySegments(ZtdfManifest manifest) {
        ZtdfManifest.IntegrityInformation integrity = manifest.encryptionInformation().integrityInformation();
        if (integrity == null || integrity.segments() == null) {
            return List.of();
        }
        List<IntegritySegment> segments = new ArrayList<>(integrity.segments().size());
        for (ZtdfManifest.Segment segment : integrity.segments()) {
            segments.add(new IntegritySegment(segment.hash(), segment.segmentSize(), segment.encryptedSegmentSize()));
        }
        return segments;
    }

    private static byte[] rootHash(ZtdfManifest manifest) {
        ZtdfManifest.IntegrityInformation integrity = manifest.encryptionInformation().integrityInformation();
        if (integrity == null || integrity.rootSignature() == null) {
            return null;
        }
        String sig = integrity.rootSignature().sig();
        if (sig == null || sig.isBlank()) {
            return null;
        }
        return Base64.getDecoder().decode(sig);
    }

    private static byte[] wrapDekWithPrivateKey(byte[] dek, RSAPrivateKey privateKey) {
        int k = (privateKey.getModulus().bitLength() + 7) / 8;
        if (dek.length > k - 11) {
            throw new IllegalArgumentException("DEK too large for client key");
        }

        byte[] em = new byte[k];
        em[0] = 0x00;
        em[1] = 0x01;
        int psLen = k - dek.length - 3;
        Arrays.fill(em, 2, 2 + psLen, (byte) 0xFF);
        em[2 + psLen] = 0x00;
        System.arraycopy(dek, 0, em, 3 + psLen, dek.length);

        java.math.BigInteger m = new java.math.BigInteger(1, em);
        java.math.BigInteger c = m.modPow(privateKey.getPrivateExponent(), privateKey.getModulus());
        byte[] out = c.toByteArray();
        if (out.length == k + 1 && out[0] == 0) {
            byte[] trimmed = new byte[k];
            System.arraycopy(out, 1, trimmed, 0, k);
            out = trimmed;
        } else if (out.length < k) {
            byte[] padded = new byte[k];
            System.arraycopy(out, 0, padded, k - out.length, out.length);
            out = padded;
        }
        return out;
    }

    private static byte[] packageZtdf(byte[] manifestBytes, byte[] payloadBytes) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (ZipOutputStream zip = new ZipOutputStream(baos)) {
                zip.putNextEntry(new ZipEntry("manifest.json"));
                zip.write(manifestBytes);
                zip.closeEntry();

                zip.putNextEntry(new ZipEntry("0.payload"));
                zip.write(payloadBytes);
                zip.closeEntry();
            }
            return baos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to package ZTDF", e);
        }
    }

    private StoredKeyPair registerNewKeyPair() {
        System.err.println("[StratiumClient] Registering new client key with Key Manager...");
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();
            Instant expiresAt = Instant.now().plus(Duration.ofDays(1));
            String ownerId = config.getSubjectId() != null ? config.getSubjectId() : config.getClientId();
            KeyMetadata metadata = keyManagerClient.registerKey(
                    ownerId,
                    PemUtils.publicKeyToPem(keyPair.getPublic()).getBytes(),
                    expiresAt
            );
            StoredKeyPair stored = new StoredKeyPair(metadata, keyPair.getPublic(), keyPair.getPrivate());
            keyStore.saveKeyPair(metadata, keyPair.getPublic(), keyPair.getPrivate());
            return stored;
        } catch (Exception e) {
            System.err.println("[StratiumClient] Key registration failed: " + e);
            throw new IllegalStateException("Failed to register client key", e);
        }
    }

    private void ensureInitialized() {
        if (currentKeyPair == null) {
            throw new IllegalStateException("Client not initialized");
        }
    }

    private static ManagedChannel buildChannel(URI uri) {
        ManagedChannelBuilder<?> builder = ManagedChannelBuilder
                .forAddress(uri.getHost(), uri.getPort() == -1 ? 443 : uri.getPort());
        if ("http".equalsIgnoreCase(uri.getScheme())) {
            builder.usePlaintext();
        }
        return builder.build();
    }
}
