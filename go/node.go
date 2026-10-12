//go:build cgo && stogas_gateway

package verifier

/*
#include <stddef.h>
#include <stdint.h>
typedef struct StogasNodeKeys StogasNodeKeys;
typedef struct StogasTlsKey StogasTlsKey;
typedef struct StogasBuffer { uint8_t *data; size_t len; } StogasBuffer;
uint32_t stogas_node_keys_new(uint8_t *, uint8_t *, StogasNodeKeys **);
uint32_t stogas_node_report_data(const StogasNodeKeys *, uint8_t, const uint8_t *, const uint8_t *, uint8_t *);
uint32_t stogas_node_boot_document(const StogasNodeKeys *, uint8_t, const uint8_t *, const uint8_t *, const uint8_t *, size_t, const uint8_t *, StogasBuffer *);
uint32_t stogas_node_sign_boot_request(const StogasNodeKeys *, uint8_t, const uint8_t *, size_t, int64_t, uint8_t *);
uint32_t stogas_node_sign_receipt(const StogasNodeKeys *, const uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, size_t, StogasBuffer *);
uint32_t stogas_node_open_provisioning(const StogasNodeKeys *, const uint8_t *, const uint8_t *, size_t, StogasBuffer *);
void stogas_node_keys_free(StogasNodeKeys *);
uint32_t stogas_tls_key_generate(StogasTlsKey **, uint8_t *);
uint32_t stogas_tls_key_sign(const StogasTlsKey *, const uint8_t *, size_t, uint8_t *);
void stogas_tls_key_free(StogasTlsKey *);
void stogas_buffer_free(StogasBuffer);
void stogas_secret_buffer_free(StogasBuffer);
*/
import "C"

import (
	"crypto/rand"
	"errors"
	"io"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

const (
	// Composite ML-DSA-65 and Ed25519 signatures for boot requests and receipts.
	signatureBytes = 3373
	// Pure ML-DSA-65 for per-connection TLS keys.
	tlsPublicKeyBytes = 1952
	tlsSignatureBytes = 3309
)

var (
	ErrGatewayInput               = errors.New("invalid gateway cryptographic input")
	ErrProvisioningAuthentication = errors.New("boot provisioning authentication failed")
	ErrGatewayCrypto              = errors.New("gateway cryptography failed")
)

func gatewayStatus(status C.uint32_t) error {
	switch status {
	case 0:
		return nil
	case 1:
		return ErrGatewayInput
	case 2:
		return ErrProvisioningAuthentication
	default:
		return ErrGatewayCrypto
	}
}

func takeBuffer(buffer C.StogasBuffer) []byte {
	defer C.stogas_buffer_free(buffer)
	return C.GoBytes(unsafe.Pointer(buffer.data), C.int(buffer.len))
}

// BootRequestPurpose selects the domain of a signed request to Control.
type BootRequestPurpose uint8

const (
	BootCertificateRenewal   BootRequestPurpose = 1
	BootRegistrationComplete BootRequestPurpose = 2
)

// NodeKeys holds the boot's signing and provisioning keys inside Rust. Its
// methods sign only receipts and boot requests; no private key reaches Go.
type NodeKeys struct {
	mu     sync.RWMutex
	handle *C.StogasNodeKeys
}

// GenerateNodeKeys derives one boot's keys from 96 bytes of random, which defaults
// to crypto/rand: 64 for the composite signing key and 32 for provisioning. Rust
// erases the seeds after deriving the keys.
func GenerateNodeKeys(random io.Reader) (*NodeKeys, error) {
	if err := checkNativeABI(); err != nil {
		return nil, err
	}
	if random == nil {
		random = rand.Reader
	}
	seeds := make([]byte, 96)
	defer clear(seeds)
	if _, err := io.ReadFull(random, seeds); err != nil {
		return nil, err
	}
	var handle *C.StogasNodeKeys
	if err := gatewayStatus(C.stogas_node_keys_new(bytePointer(seeds[:64]), bytePointer(seeds[64:]), &handle)); err != nil {
		return nil, err
	}
	return &NodeKeys{handle: handle}, nil
}

func (k *NodeKeys) call(operation func(*C.StogasNodeKeys) C.uint32_t) error {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.handle == nil {
		return ErrClosed
	}
	return gatewayStatus(operation(k.handle))
}

// ReportData commits these keys, the TLS key and Control's registration challenge.
// Environment is 1 (production) or 2 (staging).
func (k *NodeKeys) ReportData(environment byte, tlsSPKISHA256, challenge [32]byte) ([64]byte, error) {
	var data [64]byte
	err := k.call(func(handle *C.StogasNodeKeys) C.uint32_t {
		return C.stogas_node_report_data(handle, C.uint8_t(environment), bytePointer(tlsSPKISHA256[:]), bytePointer(challenge[:]), bytePointer(data[:]))
	})
	return data, err
}

// BootDocument returns the exact logged boot document for a quote over ReportData.
func (k *NodeKeys) BootDocument(environment byte, tlsSPKISHA256, challenge [32]byte, report []byte, gatewayReleaseID [32]byte) ([]byte, error) {
	var buffer C.StogasBuffer
	err := k.call(func(handle *C.StogasNodeKeys) C.uint32_t {
		return C.stogas_node_boot_document(handle, C.uint8_t(environment), bytePointer(tlsSPKISHA256[:]), bytePointer(challenge[:]),
			bytePointer(report), C.size_t(len(report)), bytePointer(gatewayReleaseID[:]), &buffer)
	})
	if err != nil {
		return nil, err
	}
	return takeBuffer(buffer), nil
}

// SignBootRequest authorizes one renewal or registration acknowledgement at issuedAt.
func (k *NodeKeys) SignBootRequest(purpose BootRequestPurpose, nodeID string, issuedAt time.Time) ([]byte, error) {
	signature := make([]byte, signatureBytes)
	id := []byte(nodeID)
	err := k.call(func(handle *C.StogasNodeKeys) C.uint32_t {
		return C.stogas_node_sign_boot_request(handle, C.uint8_t(purpose), bytePointer(id), C.size_t(len(id)), C.int64_t(issuedAt.UnixMilli()), bytePointer(signature))
	})
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// SignReceipt returns the receipt JSON for exact content hashes and the metadata
// object, whose top-level receipt member is excluded.
func (k *NodeKeys) SignReceipt(bootSHA256, requestSHA256, responseSHA256 [32]byte, metadata []byte) ([]byte, error) {
	var buffer C.StogasBuffer
	err := k.call(func(handle *C.StogasNodeKeys) C.uint32_t {
		return C.stogas_node_sign_receipt(handle, bytePointer(bootSHA256[:]), bytePointer(requestSHA256[:]), bytePointer(responseSHA256[:]),
			bytePointer(metadata), C.size_t(len(metadata)), &buffer)
	})
	if err != nil {
		return nil, err
	}
	return takeBuffer(buffer), nil
}

// OpenProvisioning authenticates and decrypts Control's envelope for this boot.
// The caller owns erasure of the returned plaintext.
func (k *NodeKeys) OpenProvisioning(bootSHA256 [32]byte, envelope []byte) ([]byte, error) {
	var buffer C.StogasBuffer
	err := k.call(func(handle *C.StogasNodeKeys) C.uint32_t {
		return C.stogas_node_open_provisioning(handle, bytePointer(bootSHA256[:]), bytePointer(envelope), C.size_t(len(envelope)), &buffer)
	})
	if err != nil {
		return nil, err
	}
	defer C.stogas_secret_buffer_free(buffer)
	return C.GoBytes(unsafe.Pointer(buffer.data), C.int(buffer.len)), nil
}

// Close erases both keys after concurrent calls finish.
func (k *NodeKeys) Close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.handle != nil {
		C.stogas_node_keys_free(k.handle)
		k.handle = nil
	}
}

// TLSKey is a fresh per-connection ML-DSA-65 key for one native TLS certificate
// and handshake. Rust erases it when the key becomes unreachable.
type TLSKey struct {
	handle *C.StogasTlsKey
	public []byte
}

// GenerateTLSKey creates one per-connection key.
func GenerateTLSKey() (*TLSKey, error) {
	var handle *C.StogasTlsKey
	public := make([]byte, tlsPublicKeyBytes)
	if err := gatewayStatus(C.stogas_tls_key_generate(&handle, bytePointer(public))); err != nil {
		return nil, err
	}
	key := &TLSKey{handle: handle, public: public}
	runtime.AddCleanup(key, func(handle *C.StogasTlsKey) { C.stogas_tls_key_free(handle) }, handle)
	return key, nil
}

// PublicKey returns the FIPS 204 encoded public key.
func (k *TLSKey) PublicKey() []byte { return append([]byte(nil), k.public...) }

// Sign signs a message with pure ML-DSA-65 and an empty context, as TLS 1.3 and X.509 require.
func (k *TLSKey) Sign(message []byte) ([]byte, error) {
	signature := make([]byte, tlsSignatureBytes)
	err := gatewayStatus(C.stogas_tls_key_sign(k.handle, bytePointer(message), C.size_t(len(message)), bytePointer(signature)))
	runtime.KeepAlive(k)
	if err != nil {
		return nil, err
	}
	return signature, nil
}
