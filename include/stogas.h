#ifndef STOGAS_H
#define STOGAS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct StogasTransport StogasTransport;
typedef struct StogasEvidence StogasEvidence;
typedef struct StogasEvidenceSnapshot StogasEvidenceSnapshot;

/* Offline evidence. Configuration: {"environment":"staging"|"prod", "root"?: {...}}, where
 * root is a root document as an environment's root file gives it: key_id, public_key,
 * rekor_public_key and, for Rekor v2 entries, rekor_v2. Omit root for the compiled Stogas
 * authority.
 * An explicit root is local caller configuration, never downloaded evidence input.
 * Calls return the same owned JSON envelope, with a fixed `code` on errors.
 * Snapshots own their verified state and may outlive refresh or the verifier.
 * Free handles exactly once, after their concurrent operations finish.
 */
char *stogas_evidence_new(const uint8_t *configuration, size_t configuration_len, StogasEvidence **output);
void stogas_evidence_free(StogasEvidence *handle);
char *stogas_evidence_refresh(const StogasEvidence *handle, const uint8_t *evidence, size_t evidence_len, int64_t now_unix_ms, StogasEvidenceSnapshot **output);
void stogas_evidence_snapshot_free(StogasEvidenceSnapshot *handle);
char *stogas_evidence_verify_logged_boot(const StogasEvidenceSnapshot *handle, const uint8_t *document, size_t document_len, const uint8_t *inclusion, size_t inclusion_len, int64_t now_unix_ms);
/* Each content digest is 64 bytes from the receipt content functions below, or empty
 * (length 0) to leave that side unchecked: a receipt then proves only the rest.
 * This appraises the logged boot at now_unix_ms; it does not establish inference time.
 * The receipt input is the complete final stogas metadata JSON, including its receipt and the
 * salt of each side checked. */
char *stogas_evidence_verify_receipt(const StogasEvidenceSnapshot *handle, const uint8_t *document, size_t document_len, const uint8_t *inclusion, size_t inclusion_len, const uint8_t *receipt, size_t receipt_len, const uint8_t *request_digest, size_t request_digest_len, const uint8_t *response_digest, size_t response_digest_len, int64_t now_unix_ms);

/* Historical appraisal authenticates the archive at its log-inclusion time.
 * These operations never install current permission or alter learned revocations. */
char *stogas_evidence_verify_archive(const StogasEvidence *handle, const uint8_t *evidence, size_t evidence_len, int64_t now_unix_ms);
char *stogas_evidence_verify_boot_archive(const StogasEvidence *handle, const uint8_t *archive, size_t archive_len, const uint8_t *evidence, size_t evidence_len, int64_t now_unix_ms);
char *stogas_evidence_verify_receipt_archive(const StogasEvidence *handle, const uint8_t *archive, size_t archive_len, const uint8_t *evidence, size_t evidence_len, const uint8_t *receipt, size_t receipt_len, const uint8_t *request_digest, size_t request_digest_len, const uint8_t *response_digest, size_t response_digest_len, int64_t now_unix_ms);

/* Receipt content: the 64-byte SHA-512 of each side's RFC 8785 form, which a receipt commits
 * to. A request leaves out its top-level encryption_keys; a buffered response leaves out its
 * top-level stogas object. A stream reader takes each complete event as sent, and digests the
 * response the stream carries; a block of comments, such as a keepalive or the receipt, changes
 * nothing. Status: 0 success, 1 not one JSON
 * object or event that a receipt can commit to, 3 an integer beyond -9007199254740991 to
 * 9007199254740991, 255 panic (discard the reader). A reader rejects every call after a
 * failure or its digest; free it exactly once. */
typedef struct StogasStreamContent StogasStreamContent;
uint32_t stogas_receipt_request_digest(const uint8_t *body, size_t body_len, uint8_t digest[64]);
uint32_t stogas_receipt_response_digest(const uint8_t *body, size_t body_len, uint8_t digest[64]);
StogasStreamContent *stogas_stream_content_new(void);
uint32_t stogas_stream_content_push(StogasStreamContent *content, const uint8_t *event, size_t event_len);
uint32_t stogas_stream_content_digest(StogasStreamContent *content, uint8_t digest[64]);
void stogas_stream_content_free(StogasStreamContent *content);

#define STOGAS_ABI_VERSION 1
uint32_t stogas_abi_version(void);

/*
 * Start one managed SDK transport. Configuration is UTF-8 JSON:
 * {
 *   "environment": "prod",
 *   "security": "tls",
 *   "max_connections": 4
 * }
 *
 * These are the defaults. security accepts tls or e2ee; staging requires a staging build.
 * Optional base_url overrides the HTTPS origin, never the compiled evidence authorities.
 * Optional proxy is a "socks5h://host:port" proxy, such as Tor's, for every connection.
 * Optional onion, true or false, reaches the environment at its onion address through proxy.
 * Connections/sessions open lazily. There is no evidence polling or inference replay.
 * On success, *transport_out owns a live
 * handle and the returned envelope contains {"base_url":"http://127.0.0.1:<port>/<capability>/v1"}.
 */
char *stogas_transport_start(
    const uint8_t *configuration,
    size_t configuration_len,
    StogasTransport **transport_out
);
/* Manual refresh returns whether the verified evidence changed. */
char *stogas_transport_refresh(const StogasTransport *transport);
/* Explicit graceful close waits up to five seconds for active work; it retains the handle. */
void stogas_transport_close(const StogasTransport *transport);
/* Release exactly once after concurrent calls finish. Finalizers may use this without waiting.
 * Explicit disposal should call close first, then free. */
void stogas_transport_free(StogasTransport *transport);

/*
 * Each operation returns an owned, NUL-terminated JSON envelope:
 *   {"ok":true,"value":...}
 *   {"ok":false,"error":"..."}
 * Release every non-NULL result with stogas_string_free.
 */
void stogas_string_free(char *value);

#ifdef __cplusplus
}
#endif

#endif
