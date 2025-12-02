package com.stratium.sdk.key;

import com.google.protobuf.Timestamp;
import com.stratium.sdk.client.BearerTokenCallCredentials;
import com.stratium.sdk.client.TokenProvider;
import key_manager.KeyManagerServiceGrpc;
import key_manager.KeyManager;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

public final class KeyManagerClient {
    private final KeyManagerServiceGrpc.KeyManagerServiceBlockingStub stub;

    public KeyManagerClient(io.grpc.ManagedChannel channel, TokenProvider tokenProvider) {
        this.stub = KeyManagerServiceGrpc.newBlockingStub(channel)
                .withCallCredentials(new BearerTokenCallCredentials(tokenProvider));
    }

    public KeyMetadata registerKey(String clientId, byte[] publicKeyPem, Instant expiresAt) {
        System.out.println("[KeyManagerClient] registerKey request for clientId=" + clientId + ", expires=" + expiresAt);
        KeyManager.RegisterClientKeyRequest request = KeyManager.RegisterClientKeyRequest.newBuilder()
                .setClientId(clientId)
                .setPublicKeyPem(new String(publicKeyPem, StandardCharsets.US_ASCII))
                .setKeyType(KeyManager.KeyType.KEY_TYPE_RSA_2048)
                .setExpiresAt(Timestamp.newBuilder()
                        .setSeconds(expiresAt.getEpochSecond())
                        .setNanos(expiresAt.getNano())
                        .build())
                .build();
        KeyManager.RegisterClientKeyResponse response = stub.registerClientKey(request);
        System.out.println("[KeyManagerClient] registerKey response keyId=" + response.getKey().getKeyId());
        return new KeyMetadata(
                response.getKey().getKeyId(),
                Instant.now(),
                expiresAt
        );
    }
}
