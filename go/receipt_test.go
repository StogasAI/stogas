//go:build cgo

package stogas

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestContentDigestsMatchTheReceiptSample(t *testing.T) {
	bytes, err := os.ReadFile("../tests/fixtures/content-receipt-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var sample struct {
		Request        string `json:"request"`
		Response       string `json:"response"`
		RequestDigest  string `json:"request_digest"`
		ResponseDigest string `json:"response_digest"`
	}
	if err := json.Unmarshal(bytes, &sample); err != nil {
		t.Fatal(err)
	}
	if digest, err := RequestDigest([]byte(sample.Request)); err != nil || hex.EncodeToString(digest[:]) != sample.RequestDigest {
		t.Fatalf("request digest %x: %v", digest, err)
	}
	if digest, err := ResponseDigest([]byte(sample.Response)); err != nil || hex.EncodeToString(digest[:]) != sample.ResponseDigest {
		t.Fatalf("response digest %x: %v", digest, err)
	}
	for body, want := range map[string]error{
		`{"seed":9007199254740993}`: ErrInexactInteger,
		`[1]`:                       ErrReceiptContent,
		`{"a":1,"a":2}`:             ErrReceiptContent,
		``:                          ErrReceiptContent,
	} {
		if _, err := RequestDigest([]byte(body)); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", body, err, want)
		}
	}
}

func TestStreamContentDigestsTheAssembledResponseOnce(t *testing.T) {
	want, err := ResponseDigest([]byte(`{"object":"chat.completion","choices":[{"index":0,"message":{"content":"Hello"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	content := NewStreamContent()
	defer content.Close()
	for _, event := range []string{
		"data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hel\"}}]}\n\n",
		"data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"}}]}\n\n",
		"data: [DONE]\n\n",
	} {
		if err := content.Push([]byte(event)); err != nil {
			t.Fatalf("%q: %v", event, err)
		}
	}
	if got, err := content.Digest(); err != nil || got != want {
		t.Fatalf("stream digest %x: %v", got, err)
	}
	if _, err := content.Digest(); !errors.Is(err, ErrReceiptContent) {
		t.Fatalf("second digest: %v", err)
	}
	inexact := NewStreamContent()
	if err := inexact.Push([]byte("data: {\"object\":\"chat.completion.chunk\",\"created\":9007199254740993}\n\n")); !errors.Is(err, ErrInexactInteger) {
		t.Fatalf("inexact integer: %v", err)
	}
	if err := inexact.Push([]byte("data: [DONE]\n\n")); !errors.Is(err, ErrReceiptContent) {
		t.Fatalf("push after a failure: %v", err)
	}
	inexact.Close()
	inexact.Close()
	if err := inexact.Push([]byte("data: [DONE]\n\n")); !errors.Is(err, ErrClosed) {
		t.Fatalf("push after close: %v", err)
	}
}
