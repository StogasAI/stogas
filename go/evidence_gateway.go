//go:build cgo && stogas_gateway

package stogas

/*
#include <stddef.h>
#include <stdint.h>
typedef struct StogasEvidenceSnapshot StogasEvidenceSnapshot;
char *stogas_evidence_verify_registration(const StogasEvidenceSnapshot *handle, const uint8_t *document, size_t document_len, const uint8_t *challenge, size_t challenge_len, int64_t now_unix_ms);
*/
import "C"

import "time"

// VerifyRegistrationAt checks hardware and the caller's one-use registration challenge
// at the registration authority's captured clock. The authority must still atomically
// consume its challenge before secret release.
func (s *EvidenceSnapshot) VerifyRegistrationAt(document []byte, challenge [32]byte, now time.Time) (BootIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var identity BootIdentity
	if s.handle == nil {
		return identity, ErrClosed
	}
	response := C.stogas_evidence_verify_registration(s.handle, bytePointer(document), C.size_t(len(document)), bytePointer(challenge[:]), 32, C.int64_t(now.UnixMilli()))
	err := decodeResponse(response, &identity)
	return identity, err
}
