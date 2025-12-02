package com.stratium.sdk.client;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public final class ZtdfParser {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ZtdfParser() {}

    public static ZtdfFile parse(byte[] ztdfBlob) {
        byte[] manifestBytes = null;
        byte[] payloadBytes = null;

        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(ztdfBlob))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (entry.getName().equals("manifest.json")) {
                    manifestBytes = zip.readAllBytes();
                } else if (entry.getName().equals("0.payload")) {
                    payloadBytes = zip.readAllBytes();
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to parse ZTDF file", e);
        }

        if (manifestBytes == null || payloadBytes == null) {
            throw new IllegalStateException("ZTDF missing manifest or payload entries");
        }

        try {
            ZtdfManifest manifest = MAPPER.readValue(manifestBytes, ZtdfManifest.class);
            return new ZtdfFile(manifest, payloadBytes);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to deserialize ZTDF manifest", e);
        }
    }
}
