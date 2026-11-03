//go:build cgo

package stogas

/*
#include <stddef.h>
#include <stdint.h>
typedef struct StogasStreamContent StogasStreamContent;
uint32_t stogas_receipt_request_digest(const uint8_t *body, size_t body_len, uint8_t *digest);
uint32_t stogas_receipt_response_digest(const uint8_t *body, size_t body_len, uint8_t *digest);
StogasStreamContent *stogas_stream_content_new(void);
uint32_t stogas_stream_content_push(StogasStreamContent *content, const uint8_t *event, size_t event_len);
uint32_t stogas_stream_content_digest(StogasStreamContent *content, uint8_t *digest);
void stogas_stream_content_free(StogasStreamContent *content);
*/
import "C"

import (
	"errors"
	"runtime"
)

func contentStatus(status C.uint32_t) error {
	switch status {
	case 0:
		return nil
	case 3:
		return ErrInexactInteger
	case 255:
		return errors.New("native verifier aborted a receipt content operation")
	default:
		return ErrReceiptContent
	}
}

// RequestDigest returns the digest that a receipt commits a request body to: its RFC 8785
// form without the top-level encryption_keys.
func RequestDigest(body []byte) (ContentDigest, error) {
	var digest ContentDigest
	status := C.stogas_receipt_request_digest(bytePointer(body), C.size_t(len(body)), bytePointer(digest[:]))
	runtime.KeepAlive(body)
	if err := contentStatus(status); err != nil {
		return ContentDigest{}, err
	}
	return digest, nil
}

// ResponseDigest returns the digest that a receipt commits a buffered response body to: its
// RFC 8785 form without the top-level stogas bag.
func ResponseDigest(body []byte) (ContentDigest, error) {
	var digest ContentDigest
	status := C.stogas_receipt_response_digest(bytePointer(body), C.size_t(len(body)), bytePointer(digest[:]))
	runtime.KeepAlive(body)
	if err := contentStatus(status); err != nil {
		return ContentDigest{}, err
	}
	return digest, nil
}

// StreamContent reads a stream's events into the response that its receipt signs: the
// chat.completion that Chat Completions chunks assemble to, or the response of a Responses
// stream's terminal event. Use it from one goroutine at a time, and Close it.
type StreamContent struct {
	handle *C.StogasStreamContent
}

// NewStreamContent starts reading a stream.
func NewStreamContent() *StreamContent {
	return &StreamContent{handle: C.stogas_stream_content_new()}
}

// Push reads one complete event as it was sent. A block of comments, such as a keepalive
// or the receipt, changes nothing. After an error every later call fails.
func (c *StreamContent) Push(event []byte) error {
	if c == nil || c.handle == nil {
		return ErrClosed
	}
	status := C.stogas_stream_content_push(c.handle, bytePointer(event), C.size_t(len(event)))
	runtime.KeepAlive(event)
	return contentStatus(status)
}

// Digest returns the digest of the response that the complete stream carries. Every later
// call fails.
func (c *StreamContent) Digest() (ContentDigest, error) {
	var digest ContentDigest
	if c == nil || c.handle == nil {
		return digest, ErrClosed
	}
	if err := contentStatus(C.stogas_stream_content_digest(c.handle, bytePointer(digest[:]))); err != nil {
		return ContentDigest{}, err
	}
	return digest, nil
}

// Close releases what the reader holds. It may be called more than once.
func (c *StreamContent) Close() {
	if c != nil && c.handle != nil {
		C.stogas_stream_content_free(c.handle)
		c.handle = nil
	}
}
