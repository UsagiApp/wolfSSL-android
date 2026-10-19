cmake_minimum_required(VERSION 3.22.1)
project(wolfssl C)

set(CMAKE_C_STANDARD 99)

# Locate wolfssl directory (git submodule or FetchContent)
set(WOLFSSL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/main/jni/wolfssl")

if(NOT EXISTS "${WOLFSSL_DIR}/src/ssl.c")
    message(STATUS "wolfSSL submodule not found at ${WOLFSSL_DIR}, downloading via FetchContent...")
    include(FetchContent)
    FetchContent_Declare(
        wolfssl_external
        GIT_REPOSITORY https://github.com/wolfSSL/wolfssl.git
        GIT_TAG        ac01707f552c611fbd135cc723b2682b3e7f80f2
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(wolfssl_external)
    set(WOLFSSL_DIR "${wolfssl_external_SOURCE_DIR}")
endif()

set(WOLFSSL_SOURCES
    ${WOLFSSL_DIR}/src/internal.c
    ${WOLFSSL_DIR}/src/ssl.c
    ${WOLFSSL_DIR}/src/tls.c
    ${WOLFSSL_DIR}/src/tls13.c
    ${WOLFSSL_DIR}/src/wolfio.c
    ${WOLFSSL_DIR}/src/keys.c
    ${WOLFSSL_DIR}/wolfcrypt/src/aes.c
    ${WOLFSSL_DIR}/wolfcrypt/src/asn.c
    ${WOLFSSL_DIR}/wolfcrypt/src/coding.c
    ${WOLFSSL_DIR}/wolfcrypt/src/ecc.c
    ${WOLFSSL_DIR}/wolfcrypt/src/error.c
    ${WOLFSSL_DIR}/wolfcrypt/src/hmac.c
    ${WOLFSSL_DIR}/wolfcrypt/src/integer.c
    ${WOLFSSL_DIR}/wolfcrypt/src/logging.c
    ${WOLFSSL_DIR}/wolfcrypt/src/random.c
    ${WOLFSSL_DIR}/wolfcrypt/src/rsa.c
    ${WOLFSSL_DIR}/wolfcrypt/src/sha.c
    ${WOLFSSL_DIR}/wolfcrypt/src/sha256.c
    ${WOLFSSL_DIR}/wolfcrypt/src/sha512.c
    ${WOLFSSL_DIR}/wolfcrypt/src/wc_port.c
    ${WOLFSSL_DIR}/wolfcrypt/src/memory.c
    ${WOLFSSL_DIR}/wolfcrypt/src/md5.c
    ${WOLFSSL_DIR}/wolfcrypt/src/des3.c
    ${WOLFSSL_DIR}/wolfcrypt/src/dh.c
    ${WOLFSSL_DIR}/wolfcrypt/src/dsa.c
    ${WOLFSSL_DIR}/wolfcrypt/src/hash.c
    ${WOLFSSL_DIR}/wolfcrypt/src/cpuid.c
    ${WOLFSSL_DIR}/wolfcrypt/src/sp_int.c
    ${WOLFSSL_DIR}/wolfcrypt/src/kdf.c
    ${WOLFSSL_DIR}/wolfcrypt/src/wolfmath.c
    ${WOLFSSL_DIR}/wolfcrypt/src/pwdbased.c
    ${WOLFSSL_DIR}/wolfcrypt/src/wc_encrypt.c
    src/main/jni/wolfssl_bridge.c
)

if(ANDROID_ABI STREQUAL "x86_64")
    list(APPEND WOLFSSL_SOURCES ${WOLFSSL_DIR}/wolfcrypt/src/sp_x86_64_asm.S)
elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
    list(APPEND WOLFSSL_SOURCES ${WOLFSSL_DIR}/wolfcrypt/src/sp_arm32.c)
elseif(ANDROID_ABI STREQUAL "arm64-v8a")
    list(APPEND WOLFSSL_SOURCES ${WOLFSSL_DIR}/wolfcrypt/src/sp_arm64.c)
endif()

add_library(wolfssl SHARED ${WOLFSSL_SOURCES})

target_include_directories(wolfssl PRIVATE
    src/main/jni
    ${WOLFSSL_DIR}
    ${WOLFSSL_DIR}/wolfssl
)

target_compile_definitions(wolfssl PRIVATE WOLFSSL_USER_SETTINGS)
target_compile_options(wolfssl PRIVATE -O3 -fomit-frame-pointer)
if(ANDROID_ABI STREQUAL "x86")
    target_compile_options(wolfssl PRIVATE -msse2)
endif()

find_library(log-lib log)
target_link_libraries(wolfssl ${log-lib})
