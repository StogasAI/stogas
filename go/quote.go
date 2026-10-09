//go:build cgo && stogas_gateway

package verifier

/*
#include <stddef.h>
#include <stdint.h>
typedef struct StogasBuffer { uint8_t *data; size_t len; } StogasBuffer;
uint32_t stogas_tls_leaf(uint8_t, const uint8_t *, const uint8_t *, const uint8_t *, uint8_t *);
uint32_t stogas_e2ee_leaf(uint8_t, const uint8_t *, const uint8_t *, uint8_t *);
uint32_t stogas_quote_batch(const uint8_t *, size_t, uint8_t *, StogasBuffer *);
uint32_t stogas_session_evidence(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, uint8_t, StogasBuffer *);
void stogas_buffer_free(StogasBuffer);
*/
import "C"

import (
	"encoding/binary"
	"unsafe"
)

// MaxQuoteBatchLeaves bounds the channels committed by one SNP report.
const MaxQuoteBatchLeaves = 1024

// TLSLeaf commits one native TLS handshake: the boot, client challenge and the
// fresh certificate key. Environment is 1 (production) or 2 (staging).
func TLSLeaf(environment byte, bootSHA256, challenge, signerSPKISHA256 [32]byte) ([64]byte, error) {
	var leaf [64]byte
	err := gatewayStatus(C.stogas_tls_leaf(C.uint8_t(environment), bytePointer(bootSHA256[:]), bytePointer(challenge[:]), bytePointer(signerSPKISHA256[:]), bytePointer(leaf[:])))
	return leaf, err
}

// E2EELeaf commits one encrypted session setup transcript.
func E2EELeaf(environment byte, bootSHA256, transcriptSHA256 [32]byte) ([64]byte, error) {
	var leaf [64]byte
	err := gatewayStatus(C.stogas_e2ee_leaf(C.uint8_t(environment), bytePointer(bootSHA256[:]), bytePointer(transcriptSHA256[:]), bytePointer(leaf[:])))
	return leaf, err
}

// QuoteBatch returns the report data committing every leaf and each leaf's
// encoded inclusion proof, in input order.
func QuoteBatch(leaves [][64]byte) ([64]byte, [][]byte, error) {
	var reportData [64]byte
	if len(leaves) == 0 || len(leaves) > MaxQuoteBatchLeaves {
		return reportData, nil, ErrGatewayInput
	}
	var buffer C.StogasBuffer
	err := gatewayStatus(C.stogas_quote_batch((*C.uint8_t)(unsafe.Pointer(&leaves[0][0])), C.size_t(len(leaves)), bytePointer(reportData[:]), &buffer))
	if err != nil {
		return reportData, nil, err
	}
	framed := takeBuffer(buffer)
	proofs := make([][]byte, len(leaves))
	for i := range proofs {
		if len(framed) < 2 || len(framed) < 2+int(binary.BigEndian.Uint16(framed)) {
			return reportData, nil, ErrGatewayCrypto
		}
		length := 2 + int(binary.BigEndian.Uint16(framed))
		proofs[i], framed = framed[2:length:length], framed[length:]
	}
	if len(framed) != 0 {
		return reportData, nil, ErrGatewayCrypto
	}
	return reportData, proofs, nil
}

// SessionEvidence encodes a quoted channel's report, proof and logged boot.
// Certificate selects the native TLS extension value instead of the setup payload.
func SessionEvidence(report, proof, bootDocument, bootInclusion []byte, certificate bool) ([]byte, error) {
	form := C.uint8_t(0)
	if certificate {
		form = 1
	}
	var buffer C.StogasBuffer
	err := gatewayStatus(C.stogas_session_evidence(bytePointer(report), C.size_t(len(report)), bytePointer(proof), C.size_t(len(proof)),
		bytePointer(bootDocument), C.size_t(len(bootDocument)), bytePointer(bootInclusion), C.size_t(len(bootInclusion)), form, &buffer))
	if err != nil {
		return nil, err
	}
	return takeBuffer(buffer), nil
}
