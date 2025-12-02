package com.stratium.sdk.samples;

import com.stratium.sdk.client.*;
import com.stratium.sdk.client.KeycloakTokenProvider;
import com.stratium.sdk.key.FileKeyStore;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

public final class Main {
    public static void main(String[] args) throws Exception {
        String keycloakUrl = System.getenv().getOrDefault("STRATIUM_KEYCLOAK_URL", "http://localhost:8080");
        String realm = System.getenv().getOrDefault("STRATIUM_KEYCLOAK_REALM", "stratium");
        String clientId = System.getenv().getOrDefault("STRATIUM_CLIENT_ID", "stratium-java-sdk-demo");
        String clientSecret = System.getenv("STRATIUM_CLIENT_SECRET");
        String username = System.getenv().getOrDefault("STRATIUM_USERNAME", "user");
        String password = System.getenv().getOrDefault("STRATIUM_PASSWORD", "password123");
        String scope = System.getenv().getOrDefault("STRATIUM_OIDC_SCOPE", "openid profile email stratium-user-profile");

        TokenProvider tokenProvider = buildTokenProvider(
                keycloakUrl, realm, clientId, clientSecret, username, password, scope
        );
        String subjectId = resolveSubjectId(tokenProvider);
        StratiumClientConfig config = StratiumClientConfig.builder()
                .keyAccessUri(java.net.URI.create("http://localhost:50053"))
                .keyManagerUri(java.net.URI.create("http://localhost:50052"))
                .clientId(clientId)
                .subjectId(subjectId)
                .realm(realm)
                .build();
        FileKeyStore keyStore = new FileKeyStore(
                Path.of(System.getProperty("user.home"), ".stratium", "keys", subjectId)
        );

        StratiumClient client = new StratiumClient(config, keyStore, tokenProvider);
        client.initialize().join();

        byte[] plaintext = "Hello Stratium".getBytes(StandardCharsets.UTF_8);
        String policyBase64 = Base64.getEncoder().encodeToString("{\"uuid\":\"92fcbdf4-833c-4914-9407-4c920b2ed1b0\",\"body\":{\"dataAttributes\":[{\"attribute\":\"http://example.com/attr/classification/value/confidential\",\"displayName\":\"Classification\",\"isDefault\":true,\"kasURL\":\"localhost:50053\"}]},\"tdfSpecVersion\":\"4.0.0\"}".getBytes(StandardCharsets.UTF_8));
        WrapOptions options = WrapOptions.builder()
                .filename("hello.txt")
                .contentType("text/plain")
                .resource("hello-resource")
                .policyBase64(policyBase64)
                .context(Map.of("department", "engineering"))
                .build();

        WrapResult wrapResult = client.wrap(plaintext, options);
        System.out.printf("Wrapped file size: %d bytes%n", wrapResult.ztdfBlob().length);

        byte[] decrypted = client.unwrap(wrapResult.ztdfBlob());
        System.out.printf("Unwrapped content: %s%n", new String(decrypted, StandardCharsets.UTF_8));
    }

    private static ManagedChannel buildChannel(java.net.URI uri) {
        ManagedChannelBuilder<?> builder = ManagedChannelBuilder
                .forAddress(uri.getHost(), uri.getPort() == -1 ? 443 : uri.getPort());
        if ("http".equalsIgnoreCase(uri.getScheme())) {
            builder.usePlaintext();
        }
        return builder.build();
    }

    private static TokenProvider buildTokenProvider(String keycloakUrl,
                                                    String realm,
                                                    String clientId,
                                                    String clientSecret,
                                                    String username,
                                                    String password,
                                                    String scope) {
        String bearer = System.getenv("STRATIUM_BEARER_TOKEN");
        String resolvedBearer = bearer;
        if (resolvedBearer == null || resolvedBearer.isBlank()) {
            resolvedBearer = readTokenFromFile();
        }
        if (resolvedBearer != null && !resolvedBearer.isBlank()) {
            final String token = resolvedBearer;
            return () -> CompletableFuture.completedFuture(token);
        }

        boolean hasUsername = username != null && !username.isBlank();
        boolean hasPassword = password != null && !password.isBlank();
        boolean hasSecret = clientSecret != null && !clientSecret.isBlank();

        if ((!hasUsername || !hasPassword) && !hasSecret) {
            throw new IllegalStateException(
                    "Set STRATIUM_BEARER_TOKEN, or provide STRATIUM_CLIENT_SECRET, or provide STRATIUM_USERNAME and STRATIUM_PASSWORD");
        }

        return KeycloakTokenProvider.builder()
                .authServerUrl(java.net.URI.create(keycloakUrl))
                .realm(realm)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .username(username)
                .password(password)
                .scope(scope)
                .build();
    }

    private static String readTokenFromFile() {
        Path tokenPath = Path.of(System.getProperty("user.home"), ".stratium", "token");
        if (!Files.isRegularFile(tokenPath)) {
            return null;
        }
        try {
            return Files.readString(tokenPath).trim();
        } catch (IOException e) {
            System.err.printf("Failed to read token file %s: %s%n", tokenPath, e.getMessage());
            return null;
        }
    }

    private static String resolveSubjectId(TokenProvider tokenProvider) {
        try {
            String token = tokenProvider.getToken().get(15, TimeUnit.SECONDS);
            return JwtUtils.extractSubject(token);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while resolving subject id", e);
        } catch (ExecutionException | TimeoutException e) {
            throw new IllegalStateException("Failed to resolve subject id from token", e);
        }
    }
}
