#include "stogas_verifier.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void require(int passed, const char *message) {
    if (!passed) { fprintf(stderr, "%s\n", message); exit(1); }
}

static void rejected(char *result, const char *code, const char *message) {
    require(result && strstr(result, "\"ok\":false") && strstr(result, code), message);
    stogas_verifier_string_free(result);
}

static char *configure(const char *configuration, StogasEvidence **evidence) {
    return stogas_evidence_new((const uint8_t *)configuration, strlen(configuration), evidence);
}

int main(void) {
    require(stogas_verifier_abi_version() == STOGAS_VERIFIER_ABI_VERSION, "Native ABI mismatch");

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
    puts("Packaged native ABI, trust boundary and owner lifetime passed");
    return 0;
}
