package ai.stogas;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

class TransportTest {
    @Test void rejectsInvalidConfigurationWithNativeCodes() {
        for (var options : List.of(Map.of("security", "unsupported"), Map.of("environment", "unsupported"), Map.of("max_connections", 0))) {
            var error = assertThrows(Transport.VerificationException.class, () -> new Transport(options));
            assertFalse(error.code().isEmpty());
        }
    }

    @Test void passesTheProxyAndOnionToTheNativeTransport() {
        var cases = Map.of(
            Map.of("proxy", "socks5://127.0.0.1:9050"), "use socks5h://",
            Map.of("proxy", "socks5h://127.0.0.1"), "needs a host and a port",
            Map.of("onion", true), "onion needs a proxy",
            Map.of("proxy", "socks5://127.0.0.1:9050", "onion", true), "use socks5h://");
        cases.forEach((options, message) -> {
            var error = assertThrows(Transport.VerificationException.class, () -> new Transport(options));
            assertTrue(error.getMessage().contains(message), error.getMessage());
        });
    }

    // STOGAS_LIVE=staging|prod sends an invalid API key through each security mode.
    @Test void liveGatewayRejectsAnInvalidKeyThroughEachSecurityMode() throws Exception {
        var environment = System.getenv("STOGAS_LIVE");
        assumeTrue(environment != null);
        var client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).proxy(HttpClient.Builder.NO_PROXY).build();
        for (var security : List.of("tls", "e2ee")) {
            Transport transport;
            try (var opened = new Transport(Map.of("environment", environment, "security", security))) {
                transport = opened;
                assertEquals("127.0.0.1", opened.baseUrl().getHost());
                var request = HttpRequest.newBuilder(URI.create(opened.baseUrl() + "/chat/completions"))
                    .timeout(Duration.ofSeconds(30))
                    .header("authorization", "Bearer stogas-status-monitor-uncredentialed")
                    .header("content-type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"model\":\"stogas-status-monitor\",\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}]}"))
                    .build();
                var response = client.send(request, HttpResponse.BodyHandlers.ofString());
                assertEquals(401, response.statusCode(), security);
                assertEquals("authentication_error", new ObjectMapper().readTree(response.body()).at("/error/type").asText(), security);
                CompletableFuture.allOf(CompletableFuture.runAsync(opened::refresh), CompletableFuture.runAsync(opened::refresh)).join();
            }
            transport.close();
            assertThrows(IllegalStateException.class, transport::refresh);
        }
    }
}
