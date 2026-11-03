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

`proxy` sends every connection to Stogas through a SOCKS5 or HTTP proxy, such as Tor's `socks5h://127.0.0.1:9050` or `http://proxy.example:3128`. A `username:password@` in the URL logs in, and Tor gives each login its own circuits. `"onion", true` also reaches the environment at the onion address that its signed evidence names, through that proxy. While the evidence names none, connections leave Tor through the proxy's exit. Your own HTTP client talks only to the local endpoint, so give it no proxy.

Keep the transport for the application's lifetime. Close your HTTP clients before closing it. `close()` is safe to repeat and allows up to five seconds for native cleanup. `refresh()` explicitly refreshes verification evidence; there is no polling. Calls after closure fail. Native verification failures preserve their reason in `Transport.VerificationException.code()`.

The OpenAI client is a separate dependency. See the Java example for typed requests, streaming, cancellation and retry configuration.
