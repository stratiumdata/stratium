package com.stratium.sdk.client;

public record WrapResult(byte[] ztdfBlob, long plaintextSize, long encryptedSize) {}
