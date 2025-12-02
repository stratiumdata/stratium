package com.stratium.sdk.crypto;

public final class CryptoException extends RuntimeException {
    private final String operation;

    public CryptoException(String operation, String message) {
        super(message);
        this.operation = operation;
    }

    public CryptoException(String operation, String message, Throwable cause) {
        super(message, cause);
        this.operation = operation;
    }

    public String getOperation() {
        return operation;
    }
}
