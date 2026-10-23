# wolfSSL-android

[![JitPack](https://jitpack.io/v/UsagiApp/wolfSSL-android.svg)](https://jitpack.io/#UsagiApp/wolfSSL-android)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

Lightweight, modern **wolfSSL (C library)** wrapper for Android with native TLS 1.3 / TLS 1.2 support, optimized for modern and legacy Android devices (API 21+).

## Usage

1. Add it to your root build.gradle at the end of repositories:

	```groovy
	allprojects {
 		repositories {
			...
			maven { url 'https://jitpack.io' }
		}
	}
 	```

2. Add the dependency

	```groovy
 	dependencies {
 		implementation("com.github.UsagiApp:wolfSSL-android:$version")
 	}
 	```

## Usage in code

1. Register Security Provider (Optional)

    ```kotlin
    WolfSSLProvider.install()
    ```

2. Use with OkHttp

    ```kotlin
    val trustFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
        init(null as KeyStore?)
    }
    
    val trustManager = trustFactory.trustManagers.first { it is X509TrustManager } as X509TrustManager
    val sslSocketFactory = WolfSSLSocketFactory(trustManager)
    val client = OkHttpClient.Builder()
        .sslSocketFactory(sslSocketFactory, trustManager)
        .build()
    ```

## License

[![GNU GPLv3 Image](https://www.gnu.org/graphics/gplv3-127x51.png)](http://www.gnu.org/licenses/gpl-3.0.en.html)

This library is licensed under the **GNU General Public License v3.0** (GPLv3), aligned with wolfSSL licensing terms.

You may copy, distribute and modify the software as long as you track changes/dates in source files. Any modifications
to or software including (via compiler) GPL-licensed code must also be made available under the GPL along with build &
install instructions. See [LICENSE](./LICENSE) for more details.
