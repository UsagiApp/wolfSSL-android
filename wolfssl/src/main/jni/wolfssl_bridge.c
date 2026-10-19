#include <jni.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/internal.h>
#include <android/log.h>

#define LOG_TAG "WolfSSL-JNI"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

typedef struct {
    int fd;
    int is_bypass;
    int hello_sent;
    int last_errno;
    int closed_by_peer;
} WolfIOContext;

static int bridge_io_send(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    WolfIOContext *io = (WolfIOContext*)ctx;
    if (io == NULL) return -1;

    if (io->is_bypass && !io->hello_sent && sz > 5 &&
        (unsigned char)buf[0] == 0x16 && (unsigned char)buf[1] == 0x03) {
        int sent1 = (int)send(io->fd, buf, 1, 0);
        if (sent1 < 0) {
            io->last_errno = errno;
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
        usleep(40000); // 40ms delay for TCP segmentation to bypass DPI
        int sent2 = (int)send(io->fd, buf + 1, sz - 1, 0);
        if (sent2 < 0) {
            io->last_errno = errno;
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
        io->hello_sent = 1;
        return sz;
    }

    int sent = (int)send(io->fd, buf, sz, 0);
    if (sent < 0) {
        int err = errno;
        io->last_errno = err;
        if (err == EAGAIN || err == EWOULDBLOCK) return WOLFSSL_CBIO_ERR_WANT_WRITE;
        if (err == ECONNRESET) return WOLFSSL_CBIO_ERR_CONN_RST;
        if (err == EINTR) return WOLFSSL_CBIO_ERR_ISR;
        if (err == EPIPE) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    return sent;
}

static int bridge_io_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    WolfIOContext *io = (WolfIOContext*)ctx;
    if (io == NULL) return -1;
    int recvd = (int)recv(io->fd, buf, sz, 0);
    if (recvd < 0) {
        int err = errno;
        io->last_errno = err;
        if (err == EAGAIN || err == EWOULDBLOCK) return WOLFSSL_CBIO_ERR_WANT_READ;
        if (err == ECONNRESET) return WOLFSSL_CBIO_ERR_CONN_RST;
        if (err == EINTR) return WOLFSSL_CBIO_ERR_ISR;
        if (err == ETIMEDOUT) return WOLFSSL_CBIO_ERR_TIMEOUT;
        if (err == EPIPE) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    if (recvd == 0) {
        io->closed_by_peer = 1;
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }
    return recvd;
}

static void throw_exception(JNIEnv *env, const char *className, const char *msg) {
    jclass cls = (*env)->FindClass(env, className);
    if (cls != NULL) {
        (*env)->ThrowNew(env, cls, msg);
        (*env)->DeleteLocalRef(env, cls);
    }
}

static void throw_tls_exception(JNIEnv *env, WOLFSSL *ssl, int err) {
    WolfIOContext *io = ssl != NULL ? (WolfIOContext*)wolfSSL_GetIOReadCtx(ssl) : NULL;
    const char *reason = wolfSSL_ERR_reason_error_string((unsigned long)err);
    if (reason == NULL) {
        reason = "SSL handshake failed";
    }

    if (err == SOCKET_ERROR_E || err == SOCKET_PEER_CLOSED_E || err == ZERO_RETURN || err == SOCKET_NODATA) {
        if (io != NULL) {
            if (io->last_errno == ECONNRESET) {
                throw_exception(env, "java/net/SocketException", "Connection reset");
                return;
            }
            if (io->last_errno == ETIMEDOUT || io->last_errno == EAGAIN || io->last_errno == EWOULDBLOCK) {
                throw_exception(env, "java/net/SocketTimeoutException", "Read timed out");
                return;
            }
            if (io->last_errno == EPIPE) {
                throw_exception(env, "java/net/SocketException", "Broken pipe");
                return;
            }
            if (io->closed_by_peer) {
                throw_exception(env, "java/net/SocketException", "Socket closed");
                return;
            }
        }
        throw_exception(env, "java/net/SocketException", "Socket closed");
        return;
    }

    if (err == WANT_READ || err == WANT_WRITE ||
        err == WOLFSSL_ERROR_WANT_READ_E || err == WOLFSSL_ERROR_WANT_WRITE_E) {
        throw_exception(env, "java/net/SocketTimeoutException", "SSL handshake timed out");
        return;
    }

    if (err == DOMAIN_NAME_MISMATCH || err == NO_PEER_CERT ||
        err == NO_PEER_KEY || err == PEER_KEY_ERROR || err == UNKNOWN_SNI_HOST_NAME_E) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Hostname or peer not verified: %s", reason);
        throw_exception(env, "javax/net/ssl/SSLPeerUnverifiedException", msg);
        return;
    }

    if (err == VERIFY_CERT_ERROR || err == NOT_CA_ERROR ||
        err == OCSP_CERT_REVOKED || err == CRL_CERT_REVOKED ||
        err == MAX_CHAIN_ERROR || err == UNSUPPORTED_CERTIFICATE) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Certificate verification failed: %s", reason);
        throw_exception(env, "javax/net/ssl/SSLHandshakeException", msg);
        return;
    }

    if (err == VERSION_ERROR) {
        throw_exception(env, "javax/net/ssl/SSLHandshakeException", "Protocol version not supported");
        return;
    }

    if (err == UNSUPPORTED_SUITE || err == MATCH_SUITE_ERROR || err == SUITES_ERROR) {
        throw_exception(env, "javax/net/ssl/SSLHandshakeException", "No matching cipher suite");
        return;
    }

    if (err == FATAL_ERROR) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Received fatal alert from server: %s", reason);
        throw_exception(env, "javax/net/ssl/SSLHandshakeException", msg);
        return;
    }

    {
        char msg[256];
        snprintf(msg, sizeof(msg), "Handshake failed: %s", reason);
        throw_exception(env, "javax/net/ssl/SSLHandshakeException", msg);
    }
}

JNIEXPORT jlong JNICALL Java_org_draken_wolfssl_WolfClient_nativeCreateContext
  (JNIEnv *env, jclass clazz) {
    wolfSSL_Init();
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (ctx == NULL) {
        LOGE("Failed to create WOLFSSL_CTX");
        return 0;
    }

    const char* modern_ciphers =
        "TLS13-AES256-GCM-SHA384:"
        "TLS13-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "DHE-RSA-AES256-GCM-SHA384:"
        "DHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-SHA384:"
        "ECDHE-RSA-AES256-SHA384:"
        "ECDHE-ECDSA-AES128-SHA256:"
        "ECDHE-RSA-AES128-SHA256:"
        "DHE-RSA-AES256-SHA256:"
        "DHE-RSA-AES128-SHA256";

    int ret = wolfSSL_CTX_set_cipher_list(ctx, modern_ciphers);
    if (ret != WOLFSSL_SUCCESS) {
        LOGD("wolfSSL_CTX_set_cipher_list returned: %d", ret);
    }

    // Java TrustManager validates certificate chain
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, 0);
    return (jlong)(intptr_t)ctx;
}

JNIEXPORT jlong JNICALL Java_org_draken_wolfssl_WolfClient_nativeCreateSSL
  (JNIEnv *env, jclass clazz, jlong ctxPtr, jint fd, jstring hostStr, jboolean isBypass) {
    WOLFSSL_CTX* ctx = (WOLFSSL_CTX*)(intptr_t)ctxPtr;
    if (ctx == NULL) return 0;

    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (ssl == NULL) return 0;

    WolfIOContext* io = (WolfIOContext*)calloc(1, sizeof(WolfIOContext));
    if (io == NULL) {
        wolfSSL_free(ssl);
        return 0;
    }
    io->fd = fd;
    io->is_bypass = isBypass ? 1 : 0;
    io->hello_sent = 0;

    wolfSSL_SSLSetIORecv(ssl, bridge_io_recv);
    wolfSSL_SSLSetIOSend(ssl, bridge_io_send);
    wolfSSL_SetIOReadCtx(ssl, io);
    wolfSSL_SetIOWriteCtx(ssl, io);

    if (hostStr != NULL) {
        const char *host = (*env)->GetStringUTFChars(env, hostStr, 0);
        if (host != NULL) {
            int is_ip = 1;
            int len = strlen(host);
            for (int i = 0; i < len; i++) {
                if (!((host[i] >= '0' && host[i] <= '9') || host[i] == '.' || host[i] == ':')) {
                    is_ip = 0;
                    break;
                }
            }
            if (!is_ip && len > 0) {
                wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, host, (unsigned short)len);
            }
            (*env)->ReleaseStringUTFChars(env, hostStr, host);
        }
    }

    return (jlong)(intptr_t)ssl;
}

JNIEXPORT void JNICALL Java_org_draken_wolfssl_WolfClient_nativeSetAlpn
  (JNIEnv *env, jclass clazz, jlong sslPtr, jstring alpnStr) {
    WOLFSSL* ssl = (WOLFSSL*)(intptr_t)sslPtr;
    if (ssl == NULL || alpnStr == NULL) return;

    const char *alpn = (*env)->GetStringUTFChars(env, alpnStr, 0);
    if (alpn == NULL) return;

    // Convert comma-separated string (e.g. "h2,http/1.1") to wire format
    char wireBuf[256];
    int wireIdx = 0;
    const char *start = alpn;
    const char *cur = alpn;

    while (*cur != '\0') {
        if (*cur == ',') {
            int segLen = cur - start;
            if (segLen > 0 && wireIdx + 1 + segLen < sizeof(wireBuf)) {
                wireBuf[wireIdx++] = (char)segLen;
                memcpy(wireBuf + wireIdx, start, segLen);
                wireIdx += segLen;
            }
            start = cur + 1;
        }
        cur++;
    }
    int lastLen = cur - start;
    if (lastLen > 0 && wireIdx + 1 + lastLen < sizeof(wireBuf)) {
        wireBuf[wireIdx++] = (char)lastLen;
        memcpy(wireBuf + wireIdx, start, lastLen);
        wireIdx += lastLen;
    }

    if (wireIdx > 0) {
        wolfSSL_UseALPN(ssl, wireBuf, wireIdx, WOLFSSL_ALPN_CONTINUE_ON_MISMATCH);
    }

    (*env)->ReleaseStringUTFChars(env, alpnStr, alpn);
}

JNIEXPORT jint JNICALL Java_org_draken_wolfssl_WolfClient_nativeHandshake
  (JNIEnv *env, jclass clazz, jlong sslPtr) {
    WOLFSSL* ssl = (WOLFSSL*)(intptr_t)sslPtr;
    if (ssl == NULL) {
        throw_exception(env, "java/net/SocketException", "Socket is closed");
        return -1;
    }
    int ret = wolfSSL_connect(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, ret);
        throw_tls_exception(env, ssl, err);
        return err;
    }
    return 1;
}

JNIEXPORT jobjectArray JNICALL Java_org_draken_wolfssl_WolfClient_nativeGetPeerCertificates
  (JNIEnv *env, jclass clazz, jlong sslPtr) {
    WOLFSSL* ssl = (WOLFSSL*)(intptr_t)sslPtr;
    if (ssl == NULL) return NULL;

    WOLFSSL_X509* cert = wolfSSL_get_peer_certificate(ssl);
    if (cert == NULL) return NULL;

    jobjectArray result = NULL;
    if (cert->derCert != NULL && cert->derCert->buffer != NULL && cert->derCert->length > 0) {
        int derSz = (int)cert->derCert->length;
        jbyteArray derArray = (*env)->NewByteArray(env, derSz);
        if (derArray != NULL) {
            (*env)->SetByteArrayRegion(env, derArray, 0, derSz, (const jbyte*)cert->derCert->buffer);
            jclass byteArrayClass = (*env)->FindClass(env, "[B");
            result = (*env)->NewObjectArray(env, 1, byteArrayClass, NULL);
            if (result != NULL) {
                (*env)->SetObjectArrayElement(env, result, 0, derArray);
            }
            (*env)->DeleteLocalRef(env, derArray);
        }
    }

    wolfSSL_FreeX509(cert);
    return result;
}

JNIEXPORT jstring JNICALL Java_org_draken_wolfssl_WolfClient_nativeGetProtocol
  (JNIEnv *env, jclass clazz, jlong sslPtr) {
    WOLFSSL* ssl = (WOLFSSL*)(intptr_t)sslPtr;
    if (ssl == NULL) return (*env)->NewStringUTF(env, "TLSv1.3");
    const char* ver = wolfSSL_get_version(ssl);
    return (*env)->NewStringUTF(env, ver ? ver : "TLSv1.3");
}

JNIEXPORT jstring JNICALL Java_org_draken_wolfssl_WolfClient_nativeGetCipherSuite
  (JNIEnv *env, jclass clazz, jlong sslPtr) {
    WOLFSSL* ssl = (WOLFSSL*)(intptr_t)sslPtr;
    if (ssl == NULL) return (*env)->NewStringUTF(env, "TLS_AES_256_GCM_SHA384");
    WOLFSSL_CIPHER* cipher = wolfSSL_get_current_cipher(ssl);
    if (cipher == NULL) return (*env)->NewStringUTF(env, "TLS_AES_256_GCM_SHA384");
    const char* name = wolfSSL_CIPHER_get_name(cipher);
    return (*env)->NewStringUTF(env, name ? name : "TLS_AES_256_GCM_SHA384");
}

JNIEXPORT jint JNICALL Java_org_draken_wolfssl_WolfClient_nativeRead
  (JNIEnv *env, jclass clazz, jlong sslPtr, jbyteArray array, jint off, jint len) {
    WOLFSSL* ssl = (WOLFSSL*)(intptr_t)sslPtr;
    if (ssl == NULL) {
        throw_exception(env, "java/net/SocketException", "Socket is closed");
        return -1;
    }

    jbyte* buf = (*env)->GetByteArrayElements(env, array, NULL);
    if (buf == NULL) return -1;

    int result = wolfSSL_read(ssl, buf + off, len);
    (*env)->ReleaseByteArrayElements(env, array, buf, 0);

    if (result < 0) {
        int err = wolfSSL_get_error(ssl, result);
        throw_tls_exception(env, ssl, err);
        return -1;
    }
    return result;
}

JNIEXPORT jint JNICALL Java_org_draken_wolfssl_WolfClient_nativeWrite
  (JNIEnv *env, jclass clazz, jlong sslPtr, jbyteArray array, jint off, jint len) {
    WOLFSSL* ssl = (WOLFSSL*)(intptr_t)sslPtr;
    if (ssl == NULL) {
        throw_exception(env, "java/net/SocketException", "Socket is closed");
        return -1;
    }

    jbyte* buf = (*env)->GetByteArrayElements(env, array, NULL);
    if (buf == NULL) return -1;

    int result = wolfSSL_write(ssl, buf + off, len);
    (*env)->ReleaseByteArrayElements(env, array, buf, JNI_ABORT);

    if (result <= 0) {
        int err = wolfSSL_get_error(ssl, result);
        throw_tls_exception(env, ssl, err);
        return -1;
    }
    return result;
}

JNIEXPORT void JNICALL Java_org_draken_wolfssl_WolfClient_nativeShutdown
  (JNIEnv *env, jclass clazz, jlong sslPtr) {
    if (sslPtr != 0) {
        wolfSSL_shutdown((WOLFSSL*)(intptr_t)sslPtr);
    }
}

JNIEXPORT void JNICALL Java_org_draken_wolfssl_WolfClient_nativeFreeSSL
  (JNIEnv *env, jclass clazz, jlong sslPtr) {
    if (sslPtr != 0) {
        WOLFSSL* ssl = (WOLFSSL*)(intptr_t)sslPtr;
        WolfIOContext* io = (WolfIOContext*)wolfSSL_GetIOReadCtx(ssl);
        if (io != NULL) {
            free(io);
        }
        wolfSSL_free(ssl);
    }
}

JNIEXPORT void JNICALL Java_org_draken_wolfssl_WolfClient_nativeFreeContext
  (JNIEnv *env, jclass clazz, jlong ctxPtr) {
    if (ctxPtr != 0) {
        wolfSSL_CTX_free((WOLFSSL_CTX*)(intptr_t)ctxPtr);
    }
}
