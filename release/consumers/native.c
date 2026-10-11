#include "stogas_verifier.h"
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

static void require(int passed, const char *message) {
    if (!passed) { fprintf(stderr, "%s\n", message); exit(1); }
}

static void rejected(char *result, const char *code, const char *message) {
    if (!result || !strstr(result, "\"ok\":false") || !strstr(result, code)) {
        fprintf(stderr, "%s: %s\n", message, result ? result : "no result");
        exit(1);
    }
    stogas_verifier_string_free(result);
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
    stogas_verifier_string_free(result);
    StogasEvidence *evidence = NULL;
    result = configure(staging, &evidence);
    require(result && strstr(result, "\"ok\":false") && !evidence, "Production package accepted staging evidence");
    stogas_verifier_string_free(result);

    // The compiled production authority loads; rejected evidence creates no owner.
    result = configure("{\"environment\":\"prod\"}", &evidence);
    require(result && strstr(result, "\"ok\":true") && evidence, "Production evidence authority unavailable");
    stogas_verifier_string_free(result);
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
        stogas_verifier_string_free(result);
        require(strncmp(response, "HTTP/1.1 401 ", 13) == 0 && strstr(response, "\"authentication_error\""),
            "The gateway did not reject the invalid key through the verified connection");
        result = stogas_transport_refresh(transport);
        require(result && strstr(result, "\"ok\":true"), "Live evidence refresh failed");
        stogas_verifier_string_free(result);
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
    require(stogas_verifier_abi_version() == STOGAS_VERIFIER_ABI_VERSION, "Native ABI mismatch");
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
