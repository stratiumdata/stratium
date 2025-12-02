package com.stratium.sdk.client;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record ZtdfManifest(
        String filename,
        @JsonProperty("contentType") String contentType,
        @JsonProperty("payloadHash") String payloadHash,
        @JsonProperty("encryptionInformation") EncryptionInformation encryptionInformation
) {
    public record EncryptionInformation(
            String type,
            @JsonProperty("keyAccess") List<EncryptionInformationKeyAccessEntry> keyAccess,
            Method method,
            @JsonProperty("integrityInformation") IntegrityInformation integrityInformation,
            String policy
    ) {}

    public record EncryptionInformationKeyAccessEntry(
            String type,
            String kid,
            @JsonProperty("wrappedKey") String wrappedKey,
            @JsonProperty("policyBinding") String policyBinding,
            String url,
            String protocol
    ) {}

    public record Method(
            String algorithm,
            @JsonProperty("isStreamable") boolean isStreamable,
            String iv
    ) {}

    public record IntegrityInformation(
            @JsonProperty("segments") List<Segment> segments,
            @JsonProperty("rootSignature") RootSignature rootSignature
    ) {}

    public record RootSignature(String alg, String sig) {}

    public record Segment(String hash,
                          @JsonProperty("segmentSize") int segmentSize,
                          @JsonProperty("encryptedSegmentSize") int encryptedSegmentSize) {}
}
