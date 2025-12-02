package com.stratium.sdk.client;

import io.grpc.CallCredentials;
import io.grpc.Metadata;
import io.grpc.Status;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

public final class BearerTokenCallCredentials extends CallCredentials {
    private static final Metadata.Key<String> AUTHORIZATION = Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
    private final TokenProvider tokenProvider;

    public BearerTokenCallCredentials(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Override
    public void applyRequestMetadata(RequestInfo requestInfo, Executor appExecutor, MetadataApplier applier) {
        CompletableFuture<String> tokenFuture = tokenProvider.getToken();
        tokenFuture.whenCompleteAsync((token, throwable) -> {
            if (throwable != null) {
                applier.fail(Status.UNAUTHENTICATED.withCause(throwable));
            } else {
                Metadata headers = new Metadata();
                headers.put(AUTHORIZATION, "Bearer " + token);
                applier.apply(headers);
            }
        }, appExecutor);
    }

    @Override
    public void thisUsesUnstableApi() {
        // no-op
    }
}
