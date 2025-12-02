package com.stratium.sdk.client;

import java.util.concurrent.CompletableFuture;

@FunctionalInterface
public interface TokenProvider {
    CompletableFuture<String> getToken();
}
