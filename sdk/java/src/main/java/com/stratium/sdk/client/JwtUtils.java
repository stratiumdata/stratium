package com.stratium.sdk.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class JwtUtils {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private JwtUtils() {
    }

    public static String extractSubject(String jwt) {
        if (jwt == null || jwt.isBlank()) {
            throw new IllegalArgumentException("JWT must not be null or empty");
        }
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("Invalid JWT format");
        }
        String payloadPart = parts[1];
        byte[] decoded = Base64.getUrlDecoder().decode(normalize(payloadPart));
        try {
            JsonNode node = OBJECT_MAPPER.readTree(decoded);
            JsonNode sub = node.get("sub");
            if (sub == null || sub.asText().isBlank()) {
                throw new IllegalArgumentException("JWT does not contain sub claim");
            }
            return sub.asText();
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse JWT payload", e);
        }
    }

    private static String normalize(String value) {
        int padding = 4 - (value.length() % 4);
        if (padding == 4) {
            return value;
        }
        StringBuilder builder = new StringBuilder(value);
        for (int i = 0; i < padding; i++) {
            builder.append('=');
        }
        return builder.toString();
    }
}
