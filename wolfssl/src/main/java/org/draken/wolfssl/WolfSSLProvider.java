package org.draken.wolfssl;

import java.security.Provider;
import java.security.Security;

public final class WolfSSLProvider extends Provider {
    public static final String PROVIDER_NAME = "WolfSSL";

    public WolfSSLProvider() {
        super(PROVIDER_NAME, 1.0, "WolfSSL JSSE TLS 1.3 Provider");
        put("SSLContext.TLS", WolfSSLContextSpi.class.getName());
        put("SSLContext.TLSv1.3", WolfSSLContextSpi.class.getName());
        put("SSLContext.TLSv1.2", WolfSSLContextSpi.class.getName());
        put("SSLContext.Default", WolfSSLContextSpi.class.getName());
    }

    public static synchronized boolean install() {
        try {
            Security.removeProvider(PROVIDER_NAME);
            Security.insertProviderAt(new WolfSSLProvider(), 1);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }
}
