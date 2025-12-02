package com.stratium.sdk.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;

class ZtdfParserTest {

    @Test
    void parsesManifestAndPayload() throws Exception {
        Map<String, Object> manifest = Map.of(
                "filename", "example.txt",
                "contentType", "text/plain",
                "encryptionInformation", Map.of(
                        "type", "split",
                        "keyAccess", new Object[]{Map.of(
                                "type", "wrapped",
                                "kid", "key-123",
                                "wrappedKey", "YmFzZTY0",
                                "policyBinding", ""
                        )},
                        "method", Map.of(
                                "algorithm", "AES-256-GCM",
                                "isStreamable", false,
                                "iv", "YWJj"
                        )
                )
        );

        byte[] manifestBytes = new ObjectMapper().writeValueAsBytes(manifest);
        byte[] payloadBytes = "payload".getBytes(StandardCharsets.UTF_8);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(baos)) {
            zip.putNextEntry(new ZipEntry("manifest.json"));
            zip.write(manifestBytes);
            zip.closeEntry();

            zip.putNextEntry(new ZipEntry("0.payload"));
            zip.write(payloadBytes);
            zip.closeEntry();
        }

        ZtdfFile ztdfFile = ZtdfParser.parse(baos.toByteArray());

        assertThat(ztdfFile.manifest().filename()).isEqualTo("example.txt");
        assertThat(ztdfFile.payload()).isEqualTo(payloadBytes);
    }
}
