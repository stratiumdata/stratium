package com.stratium.sdk.client;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

/**
 * TokenProvider implementation that retrieves OAuth2 tokens from Keycloak using either
 * the client_credentials or password grant (depending on provided credentials).
 */
public final class KeycloakTokenProvider implements TokenProvider {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final HttpClient httpClient;
    private final URI tokenEndpoint;
    private final String clientId;
    private final String clientSecret;
    private final String username;
    private final String password;
    private final String scope;
    private final boolean usePasswordGrant;
    private final AtomicReference<TokenCache> cache = new AtomicReference<>();

    private KeycloakTokenProvider(Builder builder) {
        this.httpClient = HttpClient.newHttpClient();
        this.tokenEndpoint = buildTokenEndpoint(builder.authServerUrl, builder.realm);
        this.clientId = builder.clientId;
        this.clientSecret = builder.clientSecret;
        this.username = builder.username;
        this.password = builder.password;
        this.scope = builder.scope;
        this.usePasswordGrant = this.username != null && this.password != null;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public CompletableFuture<String> getToken() {
        TokenCache existing = cache.get();
        Instant now = Instant.now();
        if (existing != null && existing.isValid(now)) {
            return CompletableFuture.completedFuture(existing.accessToken());
        }
        return CompletableFuture.supplyAsync(this::fetchAccessToken);
    }

    private synchronized String fetchAccessToken() {
        Instant now = Instant.now();
        TokenCache existing = cache.get();
        if (existing != null && existing.isValid(now)) {
            return existing.accessToken();
        }

        try {
            HttpRequest request = HttpRequest.newBuilder(tokenEndpoint)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(buildRequestBody()))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 != 2) {
                throw new IllegalStateException(
                        "Keycloak token request failed (" + response.statusCode() + "): " + response.body());
            }
            TokenResponse tokenResponse = OBJECT_MAPPER.readValue(response.body(), TokenResponse.class);
            if (tokenResponse.accessToken == null || tokenResponse.accessToken.isBlank()) {
                throw new IllegalStateException("Keycloak response missing access_token");
            }
            long ttlSeconds = tokenResponse.expiresIn > 0 ? tokenResponse.expiresIn : 60;
            TokenCache refreshed = new TokenCache(tokenResponse.accessToken, now.plusSeconds(ttlSeconds));
            cache.set(refreshed);
            return refreshed.accessToken();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to parse Keycloak token response", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while requesting Keycloak token", e);
        }
    }

    private String buildRequestBody() {
        List<String> params = new ArrayList<>();
        params.add(param("grant_type", usePasswordGrant ? "password" : "client_credentials"));
        params.add(param("client_id", clientId));
        if (clientSecret != null && !clientSecret.isBlank()) {
            params.add(param("client_secret", clientSecret));
        }
        if (usePasswordGrant) {
            params.add(param("username", username));
            params.add(param("password", password));
        }
        if (scope != null && !scope.isBlank()) {
            params.add(param("scope", scope));
        }
        return String.join("&", params);
    }

    private static String param(String key, String value) {
        return URLEncoder.encode(key, StandardCharsets.UTF_8) + "=" +
                URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static URI buildTokenEndpoint(URI base, String realm) {
        String normalized = base.toString();
        if (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return URI.create(normalized + "/realms/" + realm + "/protocol/openid-connect/token");
    }

    public static final class Builder {
        private URI authServerUrl;
        private String realm;
        private String clientId;
        private String clientSecret;
        private String username;
        private String password;
        private String scope;

        private Builder() {
        }

        public Builder authServerUrl(URI authServerUrl) {
            this.authServerUrl = authServerUrl;
            return this;
        }

        public Builder realm(String realm) {
            this.realm = realm;
            return this;
        }

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        public Builder username(String username) {
            this.username = username;
            return this;
        }

        public Builder password(String password) {
            this.password = password;
            return this;
        }

        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }

        public KeycloakTokenProvider build() {
            Objects.requireNonNull(authServerUrl, "authServerUrl");
            Objects.requireNonNull(realm, "realm");
            Objects.requireNonNull(clientId, "clientId");

            boolean hasUsername = username != null && !username.isBlank();
            boolean hasPassword = password != null && !password.isBlank();
            if (hasUsername != hasPassword) {
                throw new IllegalArgumentException("Both username and password must be provided for password grant");
            }
            if (!hasUsername && (clientSecret == null || clientSecret.isBlank())) {
                throw new IllegalArgumentException("clientSecret is required when using client_credentials grant");
            }
            return new KeycloakTokenProvider(this);
        }
    }

    private record TokenCache(String accessToken, Instant expiresAt) {
        boolean isValid(Instant now) {
            if (expiresAt == null) {
                return false;
            }
            Instant refreshThreshold = expiresAt.minusSeconds(30);
            return now.isBefore(refreshThreshold);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private static final class TokenResponse {
        @JsonProperty("access_token")
        private String accessToken;

        @JsonProperty("expires_in")
        private long expiresIn;
    }
}
