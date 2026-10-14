//go:build cgo && stogas_gateway

package stogas

/*
#include <stddef.h>
#include <stdint.h>
typedef struct StogasChannelSession StogasChannelSession;
typedef struct StogasChannelReader StogasChannelReader;
typedef struct StogasChannelWriter StogasChannelWriter;
typedef struct StogasBuffer { uint8_t *data; size_t len; } StogasBuffer;
uint32_t stogas_channel_setup(uint8_t, uint32_t, const uint8_t *, size_t, const uint8_t *, StogasChannelSession **, uint8_t *, uint8_t *, StogasBuffer *);
uint32_t stogas_channel_accept(StogasChannelSession *, uint64_t, uint8_t *, size_t, uint64_t, StogasChannelReader **, StogasChannelWriter **, size_t *, size_t *);
uint32_t stogas_channel_session_expire(StogasChannelSession *, uint64_t);
uint32_t stogas_channel_open(StogasChannelReader *, uint8_t *, size_t, uint8_t *, size_t *, size_t *);
uint32_t stogas_channel_complete(StogasChannelReader *);
uint32_t stogas_channel_seal(StogasChannelWriter *, uint8_t, const uint8_t *, size_t, StogasBuffer *);
void stogas_buffer_free(StogasBuffer);
void stogas_channel_session_free(StogasChannelSession *);
void stogas_channel_reader_free(StogasChannelReader *);
void stogas_channel_writer_free(StogasChannelWriter *);
*/
import "C"

import (
	"sync"
	"time"
	"unsafe"
)

func channelStatus(status C.uint32_t) error {
	switch status {
	case 0:
		return nil
	case 1:
		return ErrChannelRecord
	case 2:
		return ErrChannelAuthentication
	case 3:
		return ErrChannelLimit
	case 4:
		return ErrClosed
	case 5:
		return ErrChannelTruncated
	case 6:
		return ErrChannelPending
	default:
		return ErrChannelCrypto
	}
}

// ChannelSession embeds the Rust server admission and hybrid ratchet.
// It performs no I/O. Accepted streams have independent reader/writer owners.
type ChannelSession struct {
	mu      sync.Mutex
	handle  *C.StogasChannelSession
	started time.Time
}

// PrepareChannelSetup performs the server exchange without returning private
// keys or exporter secrets to Go. Environment is 1 (production) or 2 (staging,
// requiring a staging build).
func PrepareChannelSetup(environment byte, idleSeconds uint32, bootHash [32]byte, hello []byte) (*ChannelSetup, error) {
	if err := checkNativeABI(); err != nil {
		return nil, err
	}
	var result ChannelSetup
	var handle *C.StogasChannelSession
	var response C.StogasBuffer
	if err := channelStatus(C.stogas_channel_setup(C.uint8_t(environment), C.uint32_t(idleSeconds), bytePointer(hello), C.size_t(len(hello)), bytePointer(bootHash[:]), &handle, bytePointer(result.ID[:]), bytePointer(result.Transcript[:]), &response)); err != nil {
		return nil, err
	}
	defer C.stogas_buffer_free(response)
	if handle == nil || response.data == nil || response.len != 6+32+4+1120+ChannelPublicKeyBytes+32 {
		C.stogas_channel_session_free(handle)
		return nil, ErrChannelCrypto
	}
	result.Session = &ChannelSession{handle: handle, started: time.Now()}
	result.ResponsePrefix = C.GoBytes(unsafe.Pointer(response.data), C.int(response.len))
	return &result, nil
}

func (s *ChannelSession) elapsed(now time.Time) C.uint64_t {
	elapsed := now.Sub(s.started).Milliseconds()
	if elapsed < 0 {
		return 0
	}
	return C.uint64_t(elapsed)
}

// AcceptStart authenticates in place before committing the session. The returned
// metadata borrows encoded. Close both owners when the accepted exchange ends.
func (s *ChannelSession) AcceptStart(number uint64, encoded []byte) (*ChannelReader, *ChannelWriter, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil {
		return nil, nil, nil, ErrClosed
	}
	now := s.elapsed(time.Now())
	var reader *C.StogasChannelReader
	var writer *C.StogasChannelWriter
	var offset, length C.size_t
	status := C.stogas_channel_accept(s.handle, C.uint64_t(number), bytePointer(encoded), C.size_t(len(encoded)), now, &reader, &writer, &offset, &length)
	if status == 255 {
		C.stogas_channel_session_free(s.handle)
		s.handle = nil
	}
	if err := channelStatus(status); err != nil {
		return nil, nil, nil, err
	}
	if reader == nil || writer == nil || uint64(offset) > uint64(len(encoded)) || uint64(length) > uint64(len(encoded))-uint64(offset) {
		C.stogas_channel_reader_free(reader)
		C.stogas_channel_writer_free(writer)
		return nil, nil, nil, ErrChannelCrypto
	}
	return &ChannelReader{handle: reader}, &ChannelWriter{handle: writer}, encoded[int(offset):int(offset+length)], nil
}

// Expire erases old delayed-message keys during the embedding server's sweep.
func (s *ChannelSession) Expire(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle != nil && C.stogas_channel_session_expire(s.handle, s.elapsed(now)) == 255 {
		C.stogas_channel_session_free(s.handle)
		s.handle = nil
	}
}

// Close waits for admission, then erases this session. Admitted streams may finish.
func (s *ChannelSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle != nil {
		C.stogas_channel_session_free(s.handle)
		s.handle = nil
	}
}

// ChannelReader owns one admitted upload cipher.
type ChannelReader struct {
	mu     sync.Mutex
	handle *C.StogasChannelReader
}

// Open authenticates in place. Returned plaintext borrows encoded.
func (r *ChannelReader) Open(encoded []byte) (byte, []byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handle == nil {
		return 0, nil, ErrClosed
	}
	var kind C.uint8_t
	var offset, length C.size_t
	status := C.stogas_channel_open(r.handle, bytePointer(encoded), C.size_t(len(encoded)), &kind, &offset, &length)
	if status == 255 {
		C.stogas_channel_reader_free(r.handle)
		r.handle = nil
	}
	if err := channelStatus(status); err != nil {
		return 0, nil, err
	}
	if uint64(offset) > uint64(len(encoded)) || uint64(length) > uint64(len(encoded))-uint64(offset) {
		return 0, nil, ErrChannelCrypto
	}
	return byte(kind), encoded[int(offset):int(offset+length)], nil
}

// Complete requires authenticated upload completion.
func (r *ChannelReader) Complete() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handle == nil {
		return ErrClosed
	}
	status := C.stogas_channel_complete(r.handle)
	if status == 255 {
		C.stogas_channel_reader_free(r.handle)
		r.handle = nil
	}
	return channelStatus(status)
}

func (r *ChannelReader) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handle != nil {
		C.stogas_channel_reader_free(r.handle)
		r.handle = nil
	}
}

// ChannelWriter owns one independent response cipher.
type ChannelWriter struct {
	mu     sync.Mutex
	handle *C.StogasChannelWriter
}

func (w *ChannelWriter) Seal(kind byte, plaintext []byte) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.handle == nil {
		return nil, ErrClosed
	}
	var output C.StogasBuffer
	status := C.stogas_channel_seal(w.handle, C.uint8_t(kind), bytePointer(plaintext), C.size_t(len(plaintext)), &output)
	if status == 255 {
		C.stogas_channel_writer_free(w.handle)
		w.handle = nil
	}
	if err := channelStatus(status); err != nil {
		return nil, err
	}
	defer C.stogas_buffer_free(output)
	if output.data == nil || output.len > 65536 {
		return nil, ErrChannelCrypto
	}
	return C.GoBytes(unsafe.Pointer(output.data), C.int(output.len)), nil
}

func (w *ChannelWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.handle != nil {
		C.stogas_channel_writer_free(w.handle)
		w.handle = nil
	}
}
