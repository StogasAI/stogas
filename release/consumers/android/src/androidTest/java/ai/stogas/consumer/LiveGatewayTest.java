package ai.stogas.consumer;

import ai.stogas.Transport;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;

// A preview, which runs no live case, is qualified without this test. Android versions before 11
// lack List.of and Map.of, and versions before 13 lack InputStream.readAllBytes.
@RunWith(AndroidJUnit4.class)
public final class LiveGatewayTest {
    // Device Farm cannot pass test arguments, so this always uses the production gateways.
    @Test public void liveGatewayRejectsAnInvalidKeyThroughEachSecurityMode() throws Exception {
        for (var security : Arrays.asList("tls", "e2ee")) {
            var options = new HashMap<String, String>();
            options.put("environment", "prod");
            options.put("security", security);
            Transport transport;
            try (var opened = new Transport(options)) {
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
                try (var error = new BufferedReader(new InputStreamReader(connection.getErrorStream(), StandardCharsets.UTF_8))) {
                    var type = new JSONObject(error.lines().collect(Collectors.joining("\n"))).getJSONObject("error").getString("type");
                    assertEquals(security, "authentication_error", type);
                }
                CompletableFuture.allOf(CompletableFuture.runAsync(opened::refresh), CompletableFuture.runAsync(opened::refresh)).join();
            }
            transport.close();
            assertThrows(IllegalStateException.class, transport::refresh);
        }
    }
}
