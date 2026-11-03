//go:build cgo && stogas_gateway

package stogas

/*
#include <stddef.h>
#include <stdint.h>
typedef struct StogasNodeKeys StogasNodeKeys;
typedef struct StogasBuffer { uint8_t *data; size_t len; } StogasBuffer;
uint32_t stogas_log_row_leaf(const uint8_t *, size_t, uint8_t *);
uint32_t stogas_node_sign_log_batch(const StogasNodeKeys *, const uint8_t *, const uint8_t *, size_t, uint32_t, int64_t, int64_t, const uint8_t *, size_t, StogasBuffer *);
*/
import "C"

import (
	"runtime"
	"time"
	"unsafe"
)

// MaxLogBatchLeaves bounds the rows of one signed log batch, so an inclusion path holds at
// most 13 hashes.
const MaxLogBatchLeaves = 8192

// LogLeaf is one request log row's leaf in its signed batch.
type LogLeaf = [64]byte

// LogRowLeaf hashes one request log row for its batch: SHA-512 over a fixed domain and the
// row's RFC 8785 form, so whitespace and key order never change it. The row must be one JSON
// object without duplicate keys, invalid Unicode or integers beyond ±(2^53−1).
func LogRowLeaf(row []byte) (LogLeaf, error) {
	var leaf LogLeaf
	status := C.stogas_log_row_leaf(bytePointer(row), C.size_t(len(row)), bytePointer(leaf[:]))
	runtime.KeepAlive(row)
	return leaf, gatewayStatus(status)
}

// SignLogBatch seals the leaves as this boot's batch number sequence, open from openedAt until
// sealedAt, and returns the signed batch as JSON. The batch carries its root but not its leaves.
// Times are kept to the millisecond.
func (k *NodeKeys) SignLogBatch(bootSHA256 [32]byte, nodeID string, sequence uint32, openedAt, sealedAt time.Time, leaves []LogLeaf) ([]byte, error) {
	if len(leaves) == 0 || len(leaves) > MaxLogBatchLeaves {
		return nil, ErrGatewayInput
	}
	var buffer C.StogasBuffer
	id := []byte(nodeID)
	err := k.call(func(handle *C.StogasNodeKeys) C.uint32_t {
		return C.stogas_node_sign_log_batch(handle, bytePointer(bootSHA256[:]), bytePointer(id), C.size_t(len(id)), C.uint32_t(sequence),
			C.int64_t(openedAt.UnixMilli()), C.int64_t(sealedAt.UnixMilli()), (*C.uint8_t)(unsafe.Pointer(&leaves[0][0])), C.size_t(len(leaves)), &buffer)
	})
	runtime.KeepAlive(leaves)
	if err != nil {
		return nil, err
	}
	return takeBuffer(buffer), nil
}
