package com.stratium.sdk.crypto;

import java.security.Key;
import java.util.Base64;

public final class PemUtils {
    private PemUtils() {}

    public static String toPem(String type, byte[] der) {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----";
    }

    public static String publicKeyToPem(java.security.PublicKey key) {
        return toPem("PUBLIC KEY", key.getEncoded());
    }
}
