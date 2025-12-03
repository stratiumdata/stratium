package com.stratium.sdk.integration;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.stratium.sdk.client.StratiumClient;
import com.stratium.sdk.client.StratiumClientConfig;
import com.stratium.sdk.client.TokenProvider;
import com.stratium.sdk.client.WrapOptions;
import com.stratium.sdk.client.WrapResult;
import com.stratium.sdk.client.JwtUtils;
import com.stratium.sdk.key.FileKeyStore;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public final class CrossSdkTool {
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    private CrossSdkTool() {}

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: CrossSdkTool <encrypt|decrypt>");
            System.exit(1);
        }

        Request request = readRequest();
        try (InteropContext context = new InteropContext()) {
            context.initialize();
            Response response;
            switch (args[0]) {
                case "encrypt" -> response = context.handleEncrypt(request);
                case "decrypt" -> response = context.handleDecrypt(request);
                default -> throw new IllegalArgumentException("Unknown mode: " + args[0]);
            }
            writeResponse(response);
        } catch (Exception e) {
            String message = e.getMessage() != null ? e.getMessage() : e.toString();
            System.err.println(message);
            System.exit(1);
        }
    }

    private static Request readRequest() {
        try {
            return MAPPER.readValue(System.in, Request.class);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to parse JSON request", e);
        }
    }

    private static void writeResponse(Response response) throws IOException {
        MAPPER.writeValue(System.out, response);
    }

    private static final class InteropContext implements AutoCloseable {
        private final Environment env;
        private final StratiumClient client;

        InteropContext() {
            this.env = Environment.fromEnv();
            Path keyDir = resolveKeyDirectory(env.subjectId);
            FileKeyStore keyStore = new FileKeyStore(keyDir);
            this.client = new StratiumClient(env.clientConfig, keyStore, env.tokenProvider);
        }

        void initialize() {
            client.initialize().join();
        }

        Response handleEncrypt(Request req) {
            byte[] plaintext = decodeField(req.plaintext(), "plaintext");
            String policyBase64 = firstNonBlank(req.policyBase64(), env.policyBase64);
            if (policyBase64 == null || policyBase64.isBlank()) {
                throw new IllegalArgumentException("policyBase64 must be provided");
            }

            WrapOptions.Builder builder = WrapOptions.builder()
                    .filename(firstNonBlank(req.filename(), env.defaultFilename))
                    .contentType(firstNonBlank(req.contentType(), env.defaultContentType))
                    .resource(firstNonBlank(req.resource(), env.defaultResource))
                    .policyBase64(policyBase64);

            WrapResult wrapResult = client.wrap(plaintext, builder.build());
            return new Response(Base64.getEncoder().encodeToString(wrapResult.ztdfBlob()), null);
        }

        Response handleDecrypt(Request req) {
            byte[] ztdfBlob = decodeField(req.ztdf(), "ztdf");
            try {
                byte[] plaintext = client.unwrap(ztdfBlob);
                return new Response(null, Base64.getEncoder().encodeToString(plaintext));
            } catch (RuntimeException e) {
                e.printStackTrace(System.err);
                throw e;
            }
        }

        @Override
        public void close() {
            // no-op; StratiumClient manages resources internally
        }
    }

    private static Path resolveKeyDirectory(String subjectId) {
        String override = System.getenv("STRATIUM_JAVA_KEY_DIR");
        if (override != null && !override.isBlank()) {
            return Path.of(override);
        }
        Path cwd = Path.of("").toAbsolutePath();
        Path repoRoot = cwd.getParent() != null ? cwd.getParent().getParent() : cwd;
        if (repoRoot == null) {
            repoRoot = cwd;
        }
        return repoRoot.resolve("artifacts").resolve("client-keys").resolve("java");
    }

    private static final class Environment {
        final StratiumClientConfig clientConfig;
        final TokenProvider tokenProvider;
        final String policyBase64;
        final String defaultResource;
        final String defaultFilename;
        final String defaultContentType;
        final String subjectId;

        private Environment(StratiumClientConfig clientConfig,
                            TokenProvider tokenProvider,
                            String policyBase64,
                            String defaultResource,
                            String defaultFilename,
                            String defaultContentType,
                            String subjectId) {
            this.clientConfig = clientConfig;
            this.tokenProvider = tokenProvider;
            this.policyBase64 = policyBase64;
            this.defaultResource = defaultResource;
            this.defaultFilename = defaultFilename;
            this.defaultContentType = defaultContentType;
            this.subjectId = subjectId;
        }

        static Environment fromEnv() {
            String keyAccessUri = requireEnv("STRATIUM_KEY_ACCESS_URI");
            String keyManagerUri = requireEnv("STRATIUM_KEY_MANAGER_URI");
            String clientId = requireEnv("STRATIUM_CLIENT_ID");
            String realm = requireEnv("STRATIUM_KEYCLOAK_REALM");
            String keycloakUrl = requireEnv("STRATIUM_KEYCLOAK_URL");
            String scope = System.getenv().getOrDefault("STRATIUM_OIDC_SCOPE",
                    "openid profile email stratium-user-profile");
            String clientSecret = System.getenv("STRATIUM_CLIENT_SECRET");
            String username = System.getenv("STRATIUM_USERNAME");
            String password = System.getenv("STRATIUM_PASSWORD");

            TokenProvider tokenProvider = buildTokenProvider(
                    keycloakUrl, realm, clientId, clientSecret, username, password, scope
            );
            String subjectOverride = System.getenv("STRATIUM_SUBJECT_ID");
            String subjectId = (subjectOverride != null && !subjectOverride.isBlank())
                    ? subjectOverride
                    : resolveSubjectId(tokenProvider);

            StratiumClientConfig config = StratiumClientConfig.builder()
                    .keyAccessUri(URI.create(keyAccessUri))
                    .keyManagerUri(URI.create(keyManagerUri))
                    .clientId(clientId)
                    .realm(realm)
                    .subjectId(subjectId)
                    .build();

            String policy = System.getenv("STRATIUM_POLICY_BASE64");
            if (policy == null || policy.isBlank()) {
                throw new IllegalStateException("STRATIUM_POLICY_BASE64 must be set");
            }

            String resource = System.getenv().getOrDefault("STRATIUM_RESOURCE", "integration-resource");
            String filename = System.getenv().getOrDefault("STRATIUM_FILENAME", "interop.txt");
            String contentType = System.getenv().getOrDefault("STRATIUM_CONTENT_TYPE", "text/plain");

            return new Environment(config, tokenProvider, policy, resource, filename, contentType, subjectId);
        }
    }

    private static TokenProvider buildTokenProvider(String keycloakUrl,
                                                    String realm,
                                                    String clientId,
                                                    String clientSecret,
                                                    String username,
                                                    String password,
                                                    String scope) {
        String bearer = System.getenv("STRATIUM_BEARER_TOKEN");
        if (bearer != null && !bearer.isBlank()) {
            final String token = bearer;
            return () -> CompletableFuture.completedFuture(token);
        }

        return com.stratium.sdk.client.KeycloakTokenProvider.builder()
                .authServerUrl(URI.create(keycloakUrl))
                .realm(realm)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .username(username)
                .password(password)
                .scope(scope)
                .build();
    }

    private static String resolveSubjectId(TokenProvider tokenProvider) {
        try {
            String token = tokenProvider.getToken().get(30, TimeUnit.SECONDS);
            return JwtUtils.extractSubject(token);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while resolving subject id", e);
        } catch (ExecutionException | TimeoutException e) {
            throw new IllegalStateException("Failed to resolve subject id from token", e);
        }
    }

    private static String requireEnv(String key) {
        String value = System.getenv(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Environment variable " + key + " is required");
        }
        return value;
    }

    private static byte[] decodeField(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing " + name + " field");
        }
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid base64 in " + name, e);
        }
    }

    private static String firstNonBlank(String primary, String fallback) {
        if (primary != null && !primary.isBlank()) {
            return primary;
        }
        return fallback;
    }

    private record Request(String plaintext,
                           String ztdf,
                           String filename,
                           String contentType,
                           String resource,
                           String policyBase64) {
    }

    private record Response(String ztdf, String plaintext) {
    }
}
