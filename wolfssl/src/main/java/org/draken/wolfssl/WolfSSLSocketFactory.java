package org.draken.wolfssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

public class WolfSSLSocketFactory extends SSLSocketFactory {
    private final X509TrustManager trustManager;

    public WolfSSLSocketFactory() {
        this(null);
    }

    public WolfSSLSocketFactory(X509TrustManager trustManager) {
        this.trustManager = trustManager;
    }

    public X509TrustManager getTrustManager() {
        return trustManager;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return new String[]{"TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"};
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return getDefaultCipherSuites();
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        return new WolfSSLSocket(s, host, port, autoClose, trustManager);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return new WolfSSLSocket(host, port, trustManager);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return new WolfSSLSocket(host.getHostAddress(), port, trustManager);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        Socket socket = new Socket(host, port, localHost, localPort);
        return new WolfSSLSocket(socket, host, port, true, trustManager);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        Socket socket = new Socket(address, port, localAddress, localPort);
        return new WolfSSLSocket(socket, address.getHostAddress(), port, true, trustManager);
    }
}
