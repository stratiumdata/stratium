package com.stratium.sdk.client;

import com.google.protobuf.ByteString;
import key_access.KeyAccessServiceGrpc;
import key_access.KeyAccess;

import java.util.Map;

public final class KeyAccessClient {
    private final KeyAccessServiceGrpc.KeyAccessServiceBlockingStub stub;

    public KeyAccessClient(io.grpc.ManagedChannel channel, TokenProvider tokenProvider) {
        this.stub = KeyAccessServiceGrpc.newBlockingStub(channel)
                .withCallCredentials(new BearerTokenCallCredentials(tokenProvider));
    }

    public WrapDekResult wrapDek(byte[] clientWrappedDek,
                                 String resource,
                                 String action,
                                 Map<String, String> context,
                                 String policyBase64,
                                 String clientKeyId) {
        KeyAccess.WrapDEKRequest request = KeyAccess.WrapDEKRequest.newBuilder()
                .setResource(resource)
                .setDek(ByteString.copyFrom(clientWrappedDek))
                .setAction(action)
                .putAllContext(context)
                .setPolicy(policyBase64 == null ? "" : policyBase64)
                .setClientKeyId(clientKeyId)
                .build();
        KeyAccess.WrapDEKResponse response = stub.wrapDEK(request);
        return new WrapDekResult(
                response.getWrappedDek().toByteArray(),
                response.getKeyId(),
                response.getAccessGranted(),
                response.getAccessReason()
        );
    }

    public UnwrapDekResult unwrapDek(byte[] wrappedDek,
                                     String resource,
                                     String keyId,
                                     String action,
                                     Map<String, String> context,
                                     String policyBase64,
                                     String clientKeyId) {
        KeyAccess.UnwrapDEKRequest request = KeyAccess.UnwrapDEKRequest.newBuilder()
                .setResource(resource)
                .setWrappedDek(ByteString.copyFrom(wrappedDek))
                .setKeyId(keyId)
                .setAction(action)
                .putAllContext(context)
                .setPolicy(policyBase64 == null ? "" : policyBase64)
                .setClientKeyId(clientKeyId)
                .build();
        KeyAccess.UnwrapDEKResponse response = stub.unwrapDEK(request);
        return new UnwrapDekResult(
                response.getDekForSubject().toByteArray(),
                response.getAccessGranted(),
                response.getAccessReason()
        );
    }

    public record WrapDekResult(byte[] wrappedDek, String keyId, boolean accessGranted, String accessReason) {}
    public record UnwrapDekResult(byte[] encryptedDekForSubject, boolean accessGranted, String accessReason) {}
}
