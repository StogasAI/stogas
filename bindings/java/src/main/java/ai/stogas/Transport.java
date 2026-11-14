package ai.stogas;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.jna.*;
import com.sun.jna.ptr.PointerByReference;
import java.io.IOException;
import java.lang.ref.PhantomReference;
import java.lang.ref.ReferenceQueue;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** Reusable confidential transport. Configure your HTTP/OpenAI client with baseUrl(); the caller owns retry policy. */
public final class Transport implements AutoCloseable {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final State state;
    private final Owner owner;
    private final URI baseUrl;

    public Transport() { this(Collections.emptyMap()); }

    /** Options use the native names: environment, security, max_connections, base_url, proxy, onion and encryption_keys. */
    public Transport(Map<String, ?> options) {
        Api api = Loaded.API;
        if (api.stogas_abi_version() != 1) throw new IllegalStateException("Unsupported Stogas native ABI.");
        byte[] bytes;
        try { bytes = JSON.writeValueAsBytes(options); }
        catch (IOException error) { throw new IllegalArgumentException("Invalid transport options.", error); }
        PointerByReference output = new PointerByReference();
        Pointer result = api.stogas_transport_start(bytes, new SizeT(bytes.length), output);
        Pointer pointer = output.getValue();
        try {
            JsonNode value = result(result);
            if (pointer == null) throw new IllegalStateException("Native transport returned no handle.");
            baseUrl = URI.create(value.required("base_url").asText());
            state = new State(pointer);
            owner = new Owner(this, state);
        } catch (RuntimeException | Error error) {
            if (pointer != null) api.stogas_transport_free(pointer);
            throw error;
        }
    }

    public URI baseUrl() { return baseUrl; }
    public boolean refresh() {
        try {
            synchronized (state) {
                if (state.pointer == null) throw new IllegalStateException("Transport is closed.");
                return result(Loaded.API.stogas_transport_refresh(state.pointer)).booleanValue();
            }
        } finally { Owner.reachable(this); }
    }
    /** Finish all HTTP clients first. Cleanup waits at most five seconds and is safe to repeat. */
    @Override public void close() {
        synchronized (state) {
            if (state.pointer != null) Loaded.API.stogas_transport_close(state.pointer);
            owner.clean();
        }
    }

    public static final class VerificationException extends RuntimeException {
        private final String code;
        VerificationException(String message, String code) { super(message); this.code = code; }
        public String code() { return code; }
    }

    private static JsonNode result(Pointer pointer) {
        if (pointer == null) throw new IllegalStateException("Native transport returned no result.");
        try {
            JsonNode envelope = JSON.readTree(pointer.getString(0, StandardCharsets.UTF_8.name()));
            if (!envelope.required("ok").booleanValue())
                throw new VerificationException(envelope.required("error").asText(), envelope.required("code").asText());
            return envelope.required("value");
        } catch (IOException error) { throw new IllegalStateException("Invalid native response.", error); }
        finally { Loaded.API.stogas_string_free(pointer); }
    }

    private static final class State {
        private Pointer pointer;
        State(Pointer pointer) { this.pointer = pointer; }
        synchronized void free() {
            if (pointer != null) {
                Pointer owned = pointer;
                pointer = null;
                Loaded.API.stogas_transport_free(owned);
            }
        }
    }

    /**
     * Frees a transport's native state once the transport is unreachable without close(). Android
     * has java.lang.ref.Cleaner from API 33 and Reference.reachabilityFence from API 28, so this
     * does their work on every supported version.
     */
    private static final class Owner extends PhantomReference<Transport> {
        private static final ReferenceQueue<Transport> UNREACHABLE = new ReferenceQueue<>();
        // Keeps each Owner reachable until it frees its state.
        private static final Set<Owner> PENDING = ConcurrentHashMap.newKeySet();
        private static volatile Object fence;
        static {
            Thread cleaner = new Thread(() -> {
                while (true) {
                    try { ((Owner) UNREACHABLE.remove()).clean(); }
                    catch (InterruptedException ignored) { }
                }
            }, "stogas-transport-cleaner");
            cleaner.setDaemon(true);
            cleaner.start();
        }

        private final State state;
        Owner(Transport transport, State state) {
            super(transport, UNREACHABLE);
            this.state = state;
            PENDING.add(this);
        }

        void clean() {
            if (PENDING.remove(this)) {
                clear();
                state.free();
            }
        }

        /** Keeps an object reachable until this call, as a volatile write cannot be dropped. */
        static void reachable(Object value) {
            fence = value;
            fence = null;
        }
    }

    public static final class SizeT extends IntegerType {
        public SizeT() { this(0); }
        public SizeT(long value) { super(Native.SIZE_T_SIZE, value, true); }
    }
    public interface Api extends Library {
        int stogas_abi_version();
        Pointer stogas_transport_start(byte[] options, SizeT length, PointerByReference handle);
        Pointer stogas_transport_refresh(Pointer handle);
        void stogas_transport_close(Pointer handle);
        void stogas_transport_free(Pointer handle);
        void stogas_string_free(Pointer value);
    }
    private static final class Loaded {
        static final Api API = load();
        static Api load() {
            try {
                // Android installs ABI-selected AAR libraries in its native search path.
                if (Platform.isAndroid()) return Native.load("stogas_ffi", Api.class);
                String resource = Platform.RESOURCE_PREFIX;
                if (Platform.isLinux() && new String(Files.readAllBytes(Paths.get("/proc/self/maps")), StandardCharsets.US_ASCII).contains("ld-musl-"))
                    resource = resource.replace("linux-", "linux-musl-");
                var library = Native.extractFromResourcePath("/" + resource + "/" + System.mapLibraryName("stogas_ffi"), Transport.class.getClassLoader());
                return Native.load(library.getAbsolutePath(), Api.class);
            } catch (IOException error) { throw new IllegalStateException("No Stogas native library for this platform.", error); }
        }
    }
}
