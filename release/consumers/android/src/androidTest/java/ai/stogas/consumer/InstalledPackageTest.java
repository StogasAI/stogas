package ai.stogas.consumer;

import ai.stogas.Transport;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public final class InstalledPackageTest {
    @Test public void packagedNativeLibraryRejectsInvalidConfiguration() {
        for (var options : List.of(Map.of("security", "unsupported"), Map.of("max_connections", 0))) {
            var error = assertThrows(Transport.VerificationException.class, () -> new Transport(options));
            assertFalse(error.code().isEmpty());
        }
    }

    @Test public void productionPackageRejectsStagingAuthority() {
        var error = assertThrows(Transport.VerificationException.class,
            () -> new Transport(Map.of("environment", "staging")));
        assertFalse(error.code().isEmpty());
    }

    // Device Farm cannot pass test arguments, so this always uses the production gateways.
    @Test public void liveGatewayRejectsAnInvalidKeyThroughEachSecurityMode() throws Exception {
        for (var security : List.of("tls", "e2ee")) {
            Transport transport;
            try (var opened = new Transport(Map.of("environment", "prod", "security", security))) {
                transport = opened;
                assertEquals("127.0.0.1", opened.baseUrl().getHost());
                var connection = (HttpURLConnection) URI.create(opened.baseUrl() + "/chat/completions").toURL().openConnection(Proxy.NO_PROXY);
                connection.setConnectTimeout(30_000);
                connection.setReadTimeout(30_000);
                connection.setRequestMethod("POST");
                connection.setDoOutput(true);
                connection.setRequestProperty("authorization", "Bearer stogas-status-monitor-uncredentialed");
                connection.setRequestProperty("content-type", "application/json");
                try (var body = connection.getOutputStream()) {
                    body.write("{\"model\":\"stogas-status-monitor\",\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}]}".getBytes(StandardCharsets.UTF_8));
                }
                assertEquals(security, 401, connection.getResponseCode());
                try (var error = connection.getErrorStream()) {
                    var type = new JSONObject(new String(error.readAllBytes(), StandardCharsets.UTF_8)).getJSONObject("error").getString("type");
                    assertEquals(security, "authentication_error", type);
                }
                CompletableFuture.allOf(CompletableFuture.runAsync(opened::refresh), CompletableFuture.runAsync(opened::refresh)).join();
            }
            transport.close();
            assertThrows(IllegalStateException.class, transport::refresh);
        }
    }
}
