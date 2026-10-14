//go:build cgo

// Package stogas provides the Stogas SDK through the packaged native Rust library bundled with
// each tagged Go module release.
package stogas

/*
#cgo linux,amd64,!musl LDFLAGS: -L${SRCDIR}/native/linux-amd64 -l:libstogas_verifier_ffi.a -ldl -lpthread -lm
#cgo linux,arm64,!musl LDFLAGS: -L${SRCDIR}/native/linux-arm64 -l:libstogas_verifier_ffi.a -ldl -lpthread -lm
#cgo linux,amd64,musl LDFLAGS: -L${SRCDIR}/native/linux-musl-amd64 -l:libstogas_verifier_ffi.a -ldl -lpthread -lm
#cgo linux,arm64,musl LDFLAGS: -L${SRCDIR}/native/linux-musl-arm64 -l:libstogas_verifier_ffi.a -ldl -lpthread -lm
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/native/darwin-amd64 -lstogas_verifier_ffi -framework Security -framework CoreFoundation
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/native/darwin-arm64 -lstogas_verifier_ffi -framework Security -framework CoreFoundation
#cgo windows,amd64 LDFLAGS: -static-libgcc -L${SRCDIR}/native/windows-amd64 -lstogas_verifier_ffi -lws2_32 -lbcrypt -luserenv -lntdll
#cgo windows,arm64 LDFLAGS: -static-libgcc -L${SRCDIR}/native/windows-arm64 -lstogas_verifier_ffi -lws2_32 -lbcrypt -luserenv -lntdll
#include <stddef.h>
#include <stdint.h>
uint32_t stogas_verifier_abi_version(void);
void stogas_verifier_string_free(char *value);
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"unsafe"
)

// ErrClosed is returned after a verifier session has been closed.
var ErrClosed = errors.New("stogas verifier is closed")

func checkNativeABI() error {
	if version := uint32(C.stogas_verifier_abi_version()); version != 1 {
		return fmt.Errorf("native verifier ABI %d does not match required ABI 1", version)
	}
	return nil
}

type abiResponse struct {
	OK    bool            `json:"ok"`
	Value json.RawMessage `json:"value"`
	Error string          `json:"error"`
	Code  string          `json:"code"`
}

func decodeResponse(response *C.char, output any) error {
	if response == nil {
		return errors.New("native verifier returned no response")
	}
	defer C.stogas_verifier_string_free(response)
	var envelope abiResponse
	if err := json.Unmarshal([]byte(C.GoString(response)), &envelope); err != nil {
		return fmt.Errorf("invalid native verifier response: %w", err)
	}
	if !envelope.OK {
		if envelope.Error == "" {
			envelope.Error = "native verifier rejected the operation"
		}
		return &VerificationError{Code: envelope.Code, Message: envelope.Error}
	}
	if output == nil {
		return nil
	}
	if err := json.Unmarshal(envelope.Value, output); err != nil {
		return fmt.Errorf("invalid native verifier value: %w", err)
	}
	return nil
}

func bytePointer(value []byte) *C.uint8_t {
	if len(value) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&value[0]))
}
