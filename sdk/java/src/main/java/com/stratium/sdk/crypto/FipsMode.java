package com.stratium.sdk.crypto;

import java.security.Provider;
import java.security.Security;
import java.util.concurrent.atomic.AtomicBoolean;

public final class FipsMode {
    private static final AtomicBoolean ENABLED = new AtomicBoolean(false);
    private static final AtomicBoolean CONFIGURED = new AtomicBoolean(false);

    private FipsMode() {
    }

    public static void enable() {
        ENABLED.set(true);
        configureProvidersIfNeeded();
    }

    public static boolean isEnabled() {
        if (ENABLED.get()) {
            configureProvidersIfNeeded();
            return true;
        }
        String env = System.getenv("STRATIUM_FIPS_ENABLED");
        String prop = System.getProperty("stratium.fips.enabled");
        if (isTruthy(env) || isTruthy(prop)) {
            configureProvidersIfNeeded();
            return true;
        }
        return false;
    }

    private static boolean isTruthy(String value) {
        if (value == null) {
            return false;
        }
        return "true".equalsIgnoreCase(value) || "1".equals(value);
    }

    private static void configureProvidersIfNeeded() {
        if (!CONFIGURED.compareAndSet(false, true)) {
            return;
        }
        if (System.getProperty("org.bouncycastle.fips.approved_only") == null) {
            System.setProperty("org.bouncycastle.fips.approved_only", "true");
        }
        try {
            Class<?> providerClass = Class.forName("org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider");
            Provider provider = (Provider) providerClass.getDeclaredConstructor().newInstance();
            if (Security.getProvider(provider.getName()) == null) {
                Security.insertProviderAt(provider, 1);
            }
        } catch (ClassNotFoundException ignored) {
            // Optional: only configured if BCFIPS is on the classpath.
        } catch (Exception e) {
            throw new IllegalStateException("Failed to configure BCFIPS provider for FIPS mode", e);
        }
    }
}
