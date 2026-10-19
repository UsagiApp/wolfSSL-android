package org.draken.wolfssl;

import java.io.IOException;

public final class WolfClient {
    static final long globalCtxPtr;
    private static volatile boolean initialized = false;

    static {
        System.loadLibrary("wolfssl");
        globalCtxPtr = nativeCreateContext();
        initialized = (globalCtxPtr != 0);
    }

    public static boolean isInitialized() {
        return initialized;
    }

    public static native long nativeCreateContext();
    public static native long nativeCreateSSL(long ctxPtr, int fd, String host, boolean isBypass);
    public static native void nativeSetAlpn(long sslPtr, String alpnStr);
    public static native int nativeHandshake(long sslPtr) throws IOException;
    public static native byte[][] nativeGetPeerCertificates(long sslPtr);
    public static native String nativeGetProtocol(long sslPtr);
    public static native String nativeGetCipherSuite(long sslPtr);
    public static native int nativeRead(long sslPtr, byte[] b, int off, int len) throws IOException;
    public static native int nativeWrite(long sslPtr, byte[] b, int off, int len) throws IOException;
    public static native void nativeShutdown(long sslPtr);
    public static native void nativeFreeSSL(long sslPtr);
    public static native void nativeFreeContext(long ctxPtr);
}
