package org.draken.wolfssl;

import java.security.KeyManagementException;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class WolfSSLContextSpi extends SSLContextSpi {
    private X509TrustManager trustManager;
    private SecureRandom secureRandom;

    @Override
    protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {
        this.secureRandom = sr;
        if (tm != null) {
            for (TrustManager t : tm) {
                if (t instanceof X509TrustManager) {
                    this.trustManager = (X509TrustManager) t;
                    break;
                }
            }
        }
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        return new WolfSSLSocketFactory(trustManager);
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        throw new UnsupportedOperationException("Server sockets are not supported by WolfSSL client library");
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        throw new UnsupportedOperationException("SSLEngine is not supported");
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) {
        throw new UnsupportedOperationException("SSLEngine is not supported");
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        return null;
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        return null;
    }
}
