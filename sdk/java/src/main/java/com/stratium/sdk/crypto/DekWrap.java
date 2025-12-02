package com.stratium.sdk.crypto;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

/** Utility for wrapping DEKs using RSA public keys (PKCS#1 v1.5). */
public final class DekWrap {
    private DekWrap() {
    }

    public static byte[] wrapWithPublicKey(byte[] dek, RSAPublicKey publicKey) {
        int k = (publicKey.getModulus().bitLength() + 7) / 8;
        if (dek.length > k - 11) {
            throw new IllegalArgumentException("DEK too large for client key");
        }

        byte[] em = new byte[k];
        em[0] = 0x00;
        em[1] = 0x01;
        int psLen = k - dek.length - 3;
        for (int i = 0; i < psLen; i++) {
            em[2 + i] = (byte) 0xFF;
        }
        em[2 + psLen] = 0x00;
        System.arraycopy(dek, 0, em, 3 + psLen, dek.length);

        BigInteger m = new BigInteger(1, em);
        BigInteger c = m.modPow(publicKey.getPublicExponent(), publicKey.getModulus());
        byte[] out = c.toByteArray();
        if (out.length == k + 1 && out[0] == 0) {
            byte[] trimmed = new byte[k];
            System.arraycopy(out, 1, trimmed, 0, k);
            out = trimmed;
        } else if (out.length < k) {
            byte[] padded = new byte[k];
            System.arraycopy(out, 0, padded, k - out.length, out.length);
            out = padded;
        }
        if (out.length != k) {
            throw new IllegalStateException("Unexpected ciphertext length");
        }
        return out;
    }
}
