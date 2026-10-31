using System.Net;
using System.Text;
using System.Text.Json;
using Stogas;

foreach (var options in new[] {
    new TransportOptions { Security = "unsupported" },
    new TransportOptions { Environment = "unsupported" },
    new TransportOptions { MaxConnections = 0 },
})
{
    try
    {
        using var rejected = new Transport(options);
        throw new Exception("Invalid configuration opened a transport.");
    }
    catch (VerificationException error) when (error.Code.Length > 0) { }
}

foreach (var (options, message) in new[] {
    (new TransportOptions { Proxy = "socks5://127.0.0.1:9050" }, "use socks5h://"),
    (new TransportOptions { Proxy = "socks5h://127.0.0.1" }, "needs a host and a port"),
    (new TransportOptions { Onion = true }, "onion needs a proxy"),
    (new TransportOptions { Proxy = "socks5://127.0.0.1:9050", Onion = true }, "use socks5h://"),
})
{
    try
    {
        using var rejected = new Transport(options);
        throw new Exception("Invalid configuration opened a transport.");
    }
    catch (VerificationException error) when (error.Message.Contains(message, StringComparison.Ordinal)) { }
}

// STOGAS_LIVE=staging|prod sends an invalid API key through each security mode.
if (Environment.GetEnvironmentVariable("STOGAS_LIVE") is { } environment)
{
    using var client = new HttpClient(new SocketsHttpHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(30) };
    foreach (var security in new[] { "tls", "e2ee" })
    {
        var transport = new Transport(new TransportOptions { Environment = environment, Security = security });
        if (!transport.BaseUrl.IsLoopback || transport.BaseUrl.Scheme != "http") throw new Exception("Wrong local endpoint.");
        using var body = new StringContent("""{"model":"stogas-status-monitor","messages":[{"role":"user","content":"ping"}]}""", Encoding.UTF8, "application/json");
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{transport.BaseUrl}/chat/completions") { Content = body };
        request.Headers.Add("Authorization", "Bearer stogas-status-monitor-uncredentialed");
        using var response = await client.SendAsync(request);
        using var error = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        if (response.StatusCode != HttpStatusCode.Unauthorized || error.RootElement.GetProperty("error").GetProperty("type").GetString() != "authentication_error")
            throw new Exception($"The {security} gateway did not reject the invalid key: {(int)response.StatusCode}");
        await Task.WhenAll(Enumerable.Range(0, 3).Select(_ => Task.Run(() => transport.Refresh())));
        transport.Dispose();
        transport.Dispose();
        try { transport.Refresh(); throw new Exception("Disposed transport accepted a call."); }
        catch (ObjectDisposedException) { }
    }
}
Console.WriteLine("Installed native transport package passed.");
