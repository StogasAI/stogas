package ai.stogas.consumer;

import ai.stogas.Transport;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.util.List;
import java.util.Map;
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
}
