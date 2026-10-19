package org.draken.wolfssl;

import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509TrustManager;

public class WolfSSLSocket extends SSLSocket {
    private static final String TAG = "WolfSSLSocket";

    private final Socket socket;
    private final String host;
    private final int port;
    private final boolean autoClose;
    private final X509TrustManager trustManager;

    private long sslPtr = 0;
    private volatile boolean handshakeDone = false;
    private volatile boolean isClosed = false;
    private final Object stateLock = new Object();
    private int activeIoThreads = 0;

    private InputStream inputStream;
    private OutputStream outputStream;
    private X509Certificate[] peerCertificates;

    private static Field socketImplField;
    private static Field socketFdField;
    private static Field fdDescriptorField;

    static {
        try {
            socketImplField = Socket.class.getDeclaredField("impl");
            socketImplField.setAccessible(true);

            Class<?> implClass = Class.forName("java.net.SocketImpl");
            try {
                socketFdField = implClass.getDeclaredField("fd");
            } catch (NoSuchFieldException e) {
                socketFdField = implClass.getSuperclass().getDeclaredField("fd");
            }
            socketFdField.setAccessible(true);

            try {
                fdDescriptorField = FileDescriptor.class.getDeclaredField("descriptor");
            } catch (NoSuchFieldException e) {
                fdDescriptorField = FileDescriptor.class.getDeclaredField("fd");
            }
            fdDescriptorField.setAccessible(true);
        } catch (Throwable t) {
            Log.e(TAG, "Failed to reflect socket FD fields", t);
        }
    }

    public WolfSSLSocket(Socket socket, String host, int port, boolean autoClose, X509TrustManager trustManager) throws IOException {
        this.socket = socket;
        this.host = host;
        this.port = port;
        this.autoClose = autoClose;
        this.trustManager = trustManager;
        initWolfSSL();
    }

    public WolfSSLSocket(String host, int port, X509TrustManager trustManager) throws IOException {
        this(new Socket(host, port), host, port, true, trustManager);
    }

    private void initWolfSSL() throws IOException {
        if (!socket.isConnected()) {
            throw new IOException("Underlying socket must be connected.");
        }

        int fd = extractNativeFd(socket);
        if (fd < 0) {
            throw new IOException("Invalid socket file descriptor: " + fd);
        }

        boolean isBypass = socket.getClass().getSimpleName().contains("Bypass");
        sslPtr = WolfClient.nativeCreateSSL(WolfClient.globalCtxPtr, fd, host, isBypass);
        if (sslPtr == 0) {
            throw new IOException("Failed to create native wolfSSL instance");
        }
    }

    private static int extractNativeFd(Socket socket) throws IOException {
        try {
            Socket realSocket = socket;
            // Unwrap wrapper sockets (e.g. BypassTunnel)
            try {
                Field implSocketField = socket.getClass().getDeclaredField("implSocket");
                implSocketField.setAccessible(true);
                Object inner = implSocketField.get(socket);
                if (inner instanceof Socket) {
                    realSocket = (Socket) inner;
                }
            } catch (Throwable ignored) {}

            Object impl = socketImplField.get(realSocket);
            FileDescriptor fdObj = (FileDescriptor) socketFdField.get(impl);
            return fdDescriptorField.getInt(fdObj);
        } catch (Exception e) {
            throw new IOException("Reflection extraction of OS file descriptor failed: " + e.getMessage(), e);
        }
    }

    private void enterIo() throws IOException {
        synchronized (stateLock) {
            if (isClosed) {
                throw new SocketException("Socket is closed");
            }
            activeIoThreads++;
        }
    }

    private void exitIo() {
        synchronized (stateLock) {
            activeIoThreads--;
            if (isClosed && activeIoThreads == 0) {
                stateLock.notifyAll();
                if (sslPtr != 0) {
                    WolfClient.nativeFreeSSL(sslPtr);
                    sslPtr = 0;
                }
            }
        }
    }

    @Override
    public synchronized void startHandshake() throws IOException {
        if (handshakeDone) return;
        enterIo();
        try {
            int ret = WolfClient.nativeHandshake(sslPtr);
            if (ret != 1) {
                throw createHandshakeException(ret);
            }
            loadPeerCertificates();
            verifyCertificates();
            handshakeDone = true;
        } finally {
            exitIo();
        }
    }

    private IOException createHandshakeException(int ret) {
        if (ret == -308 || ret == -397 || ret == -343 || ret == -309) {
            return new SocketException("Socket closed");
        }
        if (ret == -323 || ret == -327 || ret == -2 || ret == -3) {
            return new SocketTimeoutException("SSL handshake timed out");
        }
        if (ret == -322 || ret == -345 || ret == -316 || ret == -342 || ret == -381) {
            return new SSLPeerUnverifiedException("Hostname or peer not verified");
        }
        if (ret == -326) {
            return new SSLHandshakeException("Protocol version not supported");
        }
        if (ret == -500 || ret == -501 || ret == -371) {
            return new SSLHandshakeException("No matching cipher suite");
        }
        if (ret == -313) {
            return new SSLHandshakeException("Received fatal alert from server");
        }
        return new SSLHandshakeException("Handshake failed, error code: " + ret);
    }

    private void loadPeerCertificates() {
        try {
            byte[][] derBytesList = WolfClient.nativeGetPeerCertificates(sslPtr);
            if (derBytesList != null && derBytesList.length > 0) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate[] certs = new X509Certificate[derBytesList.length];
                for (int i = 0; i < derBytesList.length; i++) {
                    certs[i] = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(derBytesList[i]));
                }
                this.peerCertificates = certs;
            }
        } catch (Throwable t) {
            Log.w(TAG, "Failed to parse peer certificates", t);
        }
    }

    private void verifyCertificates() throws SSLException {
        if (trustManager != null && peerCertificates != null && peerCertificates.length > 0) {
            try {
                trustManager.checkServerTrusted(peerCertificates, "RSA");
            } catch (CertificateException e) {
                SSLHandshakeException she = new SSLHandshakeException("Certificate verification failed: " + e.getMessage());
                she.initCause(e);
                throw she;
            }
        }
    }

    @Override
    public InputStream getInputStream() throws IOException {
        if (!handshakeDone) startHandshake();
        if (inputStream == null) {
            inputStream = new InputStream() {
                private final byte[] singleByte = new byte[1];

                @Override
                public int read() throws IOException {
                    int res = read(singleByte, 0, 1);
                    return res <= 0 ? -1 : (singleByte[0] & 0xFF);
                }

                @Override
                public int read(byte[] b, int off, int len) throws IOException {
                    if (len == 0) return 0;
                    enterIo();
                    try {
                        int res = WolfClient.nativeRead(sslPtr, b, off, len);
                        if (res < 0) {
                            throw new SocketException("Connection reset");
                        }
                        return res == 0 ? -1 : res;
                    } finally {
                        exitIo();
                    }
                }
            };
        }
        return inputStream;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        if (!handshakeDone) startHandshake();
        if (outputStream == null) {
            outputStream = new OutputStream() {
                @Override
                public void write(int b) throws IOException {
                    write(new byte[]{(byte) b}, 0, 1);
                }

                @Override
                public void write(byte[] b, int off, int len) throws IOException {
                    if (len == 0) return;
                    enterIo();
                    try {
                        int res = WolfClient.nativeWrite(sslPtr, b, off, len);
                        if (res <= 0) {
                            throw new SocketException("Socket closed");
                        }
                    } finally {
                        exitIo();
                    }
                }
            };
        }
        return outputStream;
    }

    @Override
    public void close() throws IOException {
        synchronized (stateLock) {
            if (isClosed) return;
            isClosed = true;
        }

        if (sslPtr != 0) {
            WolfClient.nativeShutdown(sslPtr);
        }

        if (autoClose) {
            try {
                socket.close();
            } catch (IOException ignored) {}
        }

        synchronized (stateLock) {
            if (activeIoThreads == 0 && sslPtr != 0) {
                WolfClient.nativeFreeSSL(sslPtr);
                sslPtr = 0;
            }
        }
    }

    @Override
    public SSLSession getSession() {
        return new SSLSession() {
            @Override public byte[] getId() { return new byte[32]; }
            @Override public SSLSessionContext getSessionContext() { return null; }
            @Override public long getCreationTime() { return System.currentTimeMillis(); }
            @Override public long getLastAccessedTime() { return System.currentTimeMillis(); }
            @Override public void invalidate() {}
            @Override public boolean isValid() { return !isClosed; }
            @Override public void putValue(String name, Object value) {}
            @Override public Object getValue(String name) { return null; }
            @Override public void removeValue(String name) {}
            @Override public String[] getValueNames() { return new String[0]; }

            @Override
            public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
                if (peerCertificates == null || peerCertificates.length == 0) {
                    throw new SSLPeerUnverifiedException("Peer not verified: no certificates received");
                }
                return peerCertificates;
            }

            @Override public Certificate[] getLocalCertificates() { return null; }

            @Override
            public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
                if (peerCertificates == null || peerCertificates.length == 0) {
                    throw new SSLPeerUnverifiedException("Peer not verified");
                }
                try {
                    javax.security.cert.X509Certificate[] chain = new javax.security.cert.X509Certificate[peerCertificates.length];
                    for (int i = 0; i < peerCertificates.length; i++) {
                        chain[i] = javax.security.cert.X509Certificate.getInstance(peerCertificates[i].getEncoded());
                    }
                    return chain;
                } catch (Exception e) {
                    throw new SSLPeerUnverifiedException(e.getMessage());
                }
            }

            @Override
            public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
                if (peerCertificates == null || peerCertificates.length == 0) {
                    throw new SSLPeerUnverifiedException("Peer not verified");
                }
                return peerCertificates[0].getSubjectX500Principal();
            }

            @Override public Principal getLocalPrincipal() { return null; }

            @Override
            public String getCipherSuite() {
                if (sslPtr != 0) {
                    String suite = WolfClient.nativeGetCipherSuite(sslPtr);
                    if (suite != null && !suite.isEmpty()) return suite;
                }
                return "TLS_AES_256_GCM_SHA384";
            }

            @Override
            public String getProtocol() {
                if (sslPtr != 0) {
                    String proto = WolfClient.nativeGetProtocol(sslPtr);
                    if (proto != null && !proto.isEmpty()) return proto;
                }
                return "TLSv1.3";
            }

            @Override public String getPeerHost() { return host; }
            @Override public int getPeerPort() { return port; }
            @Override public int getPacketBufferSize() { return 16384; }
            @Override public int getApplicationBufferSize() { return 16384; }
        };
    }

    // Socket delegate methods
    @Override public boolean isConnected() { return socket.isConnected(); }
    @Override public boolean isClosed() { return isClosed || socket.isClosed(); }
    @Override public InetAddress getInetAddress() { return socket.getInetAddress(); }
    @Override public InetAddress getLocalAddress() { return socket.getLocalAddress(); }
    @Override public int getPort() { return socket.getPort(); }
    @Override public int getLocalPort() { return socket.getLocalPort(); }
    @Override public SocketAddress getRemoteSocketAddress() { return socket.getRemoteSocketAddress(); }
    @Override public SocketAddress getLocalSocketAddress() { return socket.getLocalSocketAddress(); }
    @Override public void setTcpNoDelay(boolean on) throws SocketException { socket.setTcpNoDelay(on); }
    @Override public boolean getTcpNoDelay() throws SocketException { return socket.getTcpNoDelay(); }
    @Override public void setSoTimeout(int timeout) throws SocketException { socket.setSoTimeout(timeout); }
    @Override public int getSoTimeout() throws SocketException { return socket.getSoTimeout(); }

    // SSLSocket no-op / compatibility stubs
    @Override public String[] getSupportedCipherSuites() { return new String[]{"TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"}; }
    @Override public String[] getEnabledCipherSuites() { return getSupportedCipherSuites(); }
    @Override public void setEnabledCipherSuites(String[] suites) {}
    @Override public String[] getSupportedProtocols() { return new String[]{"TLSv1.3", "TLSv1.2"}; }
    @Override public String[] getEnabledProtocols() { return getSupportedProtocols(); }
    @Override public void setEnabledProtocols(String[] protocols) {}
    @Override public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {}
    @Override public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {}
    @Override public void setUseClientMode(boolean mode) {}
    @Override public boolean getUseClientMode() { return true; }
    @Override public void setNeedClientAuth(boolean need) {}
    @Override public boolean getNeedClientAuth() { return false; }
    @Override public void setWantClientAuth(boolean want) {}
    @Override public boolean getWantClientAuth() { return false; }
    @Override public void setEnableSessionCreation(boolean flag) {}
    @Override public boolean getEnableSessionCreation() { return true; }
}
