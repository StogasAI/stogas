package ai.stogas.consumer;

import ai.stogas.Transport;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.util.Arrays;
import java.util.Collections;
import org.junit.Test;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;

// Android versions before 11 lack List.of and Map.of.
@RunWith(AndroidJUnit4.class)
public final class InstalledPackageTest {
    @Test public void packagedNativeLibraryRejectsInvalidConfiguration() {
        for (var options : Arrays.asList(Collections.singletonMap("security", "unsupported"), Collections.singletonMap("max_connections", 0))) {
            var error = assertThrows(Transport.VerificationException.class, () -> new Transport(options));
            assertFalse(error.code().isEmpty());
        }
    }

    @Test public void productionPackageRejectsStagingAuthority() {
        var error = assertThrows(Transport.VerificationException.class,
            () -> new Transport(Collections.singletonMap("environment", "staging")));
        assertFalse(error.code().isEmpty());
    }
}
