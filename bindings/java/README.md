# Stogas for Java

The package uses the Rust verifier through JNA. It includes native libraries for 64-bit Linux, macOS and Windows. Java 17 or later is required. Kotlin, Scala and Clojure can use the same package.

```java
import ai.stogas.Transport;
import java.net.http.HttpClient;

try (var transport = new Transport()) {
    var baseUrl = transport.baseUrl();
    // Configure your HTTP or OpenAI client with baseUrl and your application retry policy.
}
```

The default is native attested TLS. Use `new Transport(Map.of("security", "e2ee"))` for binary E2EE. Other options are `max_connections` and `base_url`; the latter changes the inference origin without changing trusted evidence authorities. Staging requires a separately built staging library.

`proxy` sends every connection to Stogas through a SOCKS5 proxy, such as Tor's `socks5h://127.0.0.1:9050`. `"onion", true` also reaches the environment at its onion address through that proxy. Your own HTTP client talks only to the local endpoint, so give it no proxy.

Keep the transport for the application's lifetime. Close your HTTP clients before closing it. `close()` is safe to repeat and allows up to five seconds for native cleanup. `refresh()` explicitly refreshes verification evidence; there is no polling. Calls after closure fail. Native verification failures preserve their reason in `Transport.VerificationException.code()`.

The OpenAI client is a separate dependency. See the Java example for typed requests, streaming, cancellation and retry configuration.
