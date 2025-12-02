package com.stratium.sdk.ztdf;

import java.util.Objects;

/**
 * Simple DTO representing a ZTDF integrity segment entry.
 */
public final class IntegritySegment {
    private final String hashBase64;
    private final int segmentSize;
    private final int encryptedSegmentSize;

    public IntegritySegment(String hashBase64, int segmentSize, int encryptedSegmentSize) {
        this.hashBase64 = Objects.requireNonNull(hashBase64, "hashBase64");
        this.segmentSize = segmentSize;
        this.encryptedSegmentSize = encryptedSegmentSize;
    }

    public String getHashBase64() {
        return hashBase64;
    }

    public int getSegmentSize() {
        return segmentSize;
    }

    public int getEncryptedSegmentSize() {
        return encryptedSegmentSize;
    }
}
