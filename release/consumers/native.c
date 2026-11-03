#include "stogas.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
typedef SOCKET Socket;
#define close_socket closesocket
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int Socket;
#define INVALID_SOCKET (-1)
#define close_socket close
#endif

// A caller-owned offline root, the hardware session fixture's, which the managed transport
// never accepts. release/test_consumers.py keeps it equal to the fixture's.
static const char OFFLINE_ROOT[] =
    "{\"environment\":\"prod\",\"root\":{"
    "\"key_id\":\"stogas-fixture-root-20260920\","
    "\"rekor_public_key\":\"MCowBQYDK2VwAyEAaefJGJavXbTdsx1qhqIWQxIKLTxT2fKFbRhfP5QKRF0=\","
    "\"public_key\":\""
    "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"
    "RoibgrDmkPyIwShmBS6j6gQrH3mIvKWuCA=="
    "\"}}";

static void require(int passed, const char *message) {
    if (!passed) { fprintf(stderr, "%s\n", message); exit(1); }
}

static void rejected(char *result, const char *code, const char *message) {
    if (!result || !strstr(result, "\"ok\":false") || !strstr(result, code)) {
        fprintf(stderr, "%s: %s\n", message, result ? result : "no result");
        exit(1);
    }
    stogas_string_free(result);
}

static char *configure(const char *configuration, StogasEvidence **evidence) {
    return stogas_evidence_new((const uint8_t *)configuration, strlen(configuration), evidence);
}

static void offline(void) {
    // A production package never starts staging transport or trusts the staging authority.
    StogasTransport *transport = NULL;
    const char *staging = "{\"environment\":\"staging\"}";
    char *result = stogas_transport_start((const uint8_t *)staging, strlen(staging), &transport);
    require(result && strstr(result, "\"ok\":false") && !transport, "Production package accepted staging transport");
    stogas_string_free(result);
    StogasEvidence *evidence = NULL;
    result = configure(staging, &evidence);
    require(result && strstr(result, "\"ok\":false") && !evidence, "Production package accepted staging evidence");
    stogas_string_free(result);

    // The compiled production authority loads once its root names a Rekor key. Until then it
    // fails closed for that reason alone and creates no owner; the live case, which every full
    // release passes, needs it to load.
    result = configure("{\"environment\":\"prod\"}", &evidence);
    require(result && (strstr(result, "\"ok\":true") ? evidence != NULL
        : evidence == NULL && strstr(result, "rekor_public_key") != NULL),
        "Production evidence authority failed for another reason");
    stogas_string_free(result);
    stogas_evidence_free(evidence);

    // Rejected evidence creates no owner.
    result = configure(OFFLINE_ROOT, &evidence);
    require(result && strstr(result, "\"ok\":true") && evidence, "The offline root was refused");
    stogas_string_free(result);
    StogasEvidenceSnapshot *snapshot = NULL;
    static const uint8_t malformed[] = "{\"body\":";
    rejected(stogas_evidence_refresh(evidence, malformed, sizeof(malformed) - 1, 1, &snapshot),
        "\"code\":\"invalid_evidence\"", "Malformed evidence was not rejected");
    require(!snapshot, "Rejected evidence returned a snapshot");
    rejected(stogas_evidence_verify_archive(evidence, malformed, sizeof(malformed) - 1, 1),
        "\"code\":\"invalid_evidence\"", "Malformed archive was not rejected");
    rejected(stogas_evidence_verify_logged_boot(NULL, NULL, 0, NULL, 0, 1),
        "\"code\":\"invalid_operation\"", "Missing snapshot was not rejected");
    stogas_evidence_free(evidence);
}

// Send a chat completion with an invalid API key through the loopback endpoint.
static void post_invalid_key(const char *started, char *response, size_t capacity) {
    const char *field = strstr(started, "\"base_url\":\"");
    unsigned port = 0;
    char path[256];
    require(field && sscanf(field + strlen("\"base_url\":\""), "http://127.0.0.1:%u%255[^\"]", &port, path) == 2
        && port > 0 && port < 65536, "Transport returned an unexpected base URL");
    static const char body[] = "{\"model\":\"stogas-status-monitor\",\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}]}";
    char request[1024];
    int length = snprintf(request, sizeof(request),
        "POST %s/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
        "Authorization: Bearer stogas-status-monitor-uncredentialed\r\nContent-Type: application/json\r\n"
        "Content-Length: %u\r\nConnection: close\r\n\r\n%s", path, port, (unsigned)(sizeof(body) - 1), body);
    require(length > 0 && (size_t)length < sizeof(request), "Request does not fit");
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    Socket connection = socket(AF_INET, SOCK_STREAM, 0);
    require(connection != INVALID_SOCKET && connect(connection, (struct sockaddr *)&address, sizeof(address)) == 0,
        "Could not connect to the loopback endpoint");
    require(send(connection, request, length, 0) == length, "Could not send the request");
    size_t used = 0;
    int received;
    while (used + 1 < capacity && (received = (int)recv(connection, response + used, (int)(capacity - 1 - used), 0)) > 0)
        used += (size_t)received;
    response[used] = '\0';
    close_socket(connection);
}

static void live(const char *environment) {
#ifdef _WIN32
    WSADATA winsock;
    require(WSAStartup(MAKEWORD(2, 2), &winsock) == 0, "Winsock is unavailable");
#endif
    static const char *const modes[] = {"tls", "e2ee"};
    for (size_t index = 0; index < 2; index++) {
        char configuration[128];
        snprintf(configuration, sizeof(configuration), "{\"environment\":\"%s\",\"security\":\"%s\"}", environment, modes[index]);
        StogasTransport *transport = NULL;
        char *result = stogas_transport_start((const uint8_t *)configuration, strlen(configuration), &transport);
        if (!result || !strstr(result, "\"ok\":true") || !transport) {
            fprintf(stderr, "Live %s transport did not start: %s\n", modes[index], result ? result : "no result");
            exit(1);
        }
        char response[8192];
        post_invalid_key(result, response, sizeof(response));
        stogas_string_free(result);
        require(strncmp(response, "HTTP/1.1 401 ", 13) == 0 && strstr(response, "\"authentication_error\""),
            "The gateway did not reject the invalid key through the verified connection");
        result = stogas_transport_refresh(transport);
        require(result && strstr(result, "\"ok\":true"), "Live evidence refresh failed");
        stogas_string_free(result);
        stogas_transport_close(transport);
        stogas_transport_close(transport);
        rejected(stogas_transport_refresh(transport), "\"code\":\"invalid_operation\"", "A closed transport accepted a refresh");
        stogas_transport_free(transport);
    }
#ifdef _WIN32
    WSACleanup();
#endif
}

// Without STOGAS_LIVE, test the installed production package offline. With
// STOGAS_LIVE=staging|prod, send requests through that environment's gateways.
int main(void) {
    require(stogas_abi_version() == STOGAS_ABI_VERSION, "Native ABI mismatch");
    const char *environment = getenv("STOGAS_LIVE");
    if (environment) {
        require(strcmp(environment, "staging") == 0 || strcmp(environment, "prod") == 0, "STOGAS_LIVE must be staging or prod");
        live(environment);
        puts("Packaged native transport reached the gateway through attested TLS and E2EE");
    } else {
        offline();
        puts("Packaged native ABI, trust boundary and owner lifetime passed");
    }
    return 0;
}
