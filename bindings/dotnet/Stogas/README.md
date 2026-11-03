# Stogas transport for .NET

Use the verified transport with your preferred OpenAI or HTTP client. The package uses the same Rust verifier as the Stogas CLI; it does not implement a second inference API.

```csharp
using Stogas;

using var transport = new Transport();
using var http = new HttpClient(new SocketsHttpHandler
{
    UseProxy = false,
    AllowAutoRedirect = false
});
// Set your client's base URL to transport.BaseUrl and choose its retry policy.
```

`TransportOptions` selects `Security` (`tls` or `e2ee`) and `MaxConnections` (default 4). `Environment` defaults to `prod`; staging requires a staging native build. Initialization verifies evidence before returning. `Refresh()` refreshes evidence without replaying requests. `VerificationException.Code` is the structured native error code.

`Proxy` sends every connection to Stogas through a SOCKS5 or HTTP proxy, such as Tor's `socks5h://127.0.0.1:9050` or `http://proxy.example:3128`. A `username:password@` in the URL logs in, and Tor gives each login its own circuits. `Onion = true` also reaches the environment at the onion address that its signed evidence names, through that proxy. While the evidence names none, connections leave Tor through the proxy's exit. Keep `UseProxy = false` on your own client, which talks only to the local endpoint.

Dispose the transport after all clients using it finish. Disposal is safe to repeat and allows up to five seconds for graceful cleanup. The OpenAI client owns retry policy; interrupted inference may already have executed.

The native package supports 64-bit Linux, macOS and Windows targets. Mobile targets are not included.
