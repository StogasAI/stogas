//go:build cgo

package verifier

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	ref "github.com/StogasAI/verifier/go/testutil/channeltest"
)

type channelVectorRecord struct {
	Kind      byte   `json:"kind"`
	Plaintext string `json:"plaintext_hex"`
	Encoded   string `json:"encoded_hex"`
}

type channelFixture struct {
	Root      string                `json:"root_hex"`
	ID        string                `json:"session_id_hex"`
	Initial   string                `json:"initial_private_hex"`
	Alice     string                `json:"alice_seed_hex"`
	RootAfter string                `json:"after_request_root_hex"`
	Request   []channelVectorRecord `json:"request"`
	Response  []channelVectorRecord `json:"response"`
}

func channelVector(t *testing.T) channelFixture {
	t.Helper()
	encoded, err := os.ReadFile("../tests/fixtures/channel-exchange.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector channelFixture
	if err := json.Unmarshal(encoded, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

// Independent CIRCL/Go decryption of fresh Rust response keys and headers.
func channelResponseCipher(t *testing.T, v channelFixture, encoded []byte) (cipher.AEAD, [12]byte) {
	t.Helper()
	if len(encoded) < 6+ref.HeaderBytes+17 {
		t.Fatal("short response")
	}
	initial := ref.KDF(nil, channelHex(t, v.Root), ":Initialization", 96)
	header, err := ref.OpenHeader(initial[64:], encoded[6:6+ref.HeaderBytes])
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint64(header[2328:2336]) != 0 || binary.BigEndian.Uint64(header[2336:2344]) != 0 {
		t.Fatal("unexpected response counters")
	}
	alice := ref.KeyPair(channelHex(t, v.Alice))
	root := ref.KDF(channelHex(t, v.RootAfter), append(alice.Agree(header[:ref.PublicBytes]), alice.Decap(header[ref.PublicBytes:2328])...), ":Root", 96)
	_, secret, _ := ref.Chain(root[32:64])
	aead, nonce := ref.RecordMaterial(secret, channelHex(t, v.ID), 0, 2)
	return aead, [12]byte(nonce)
}
func channelHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestChannelForgedGapDoesNotConsumeSessionState(t *testing.T) {
	v := channelVector(t)
	session, err := NewChannelSession([32]byte(channelHex(t, v.Root)), [32]byte(channelHex(t, v.ID)), [32]byte(channelHex(t, v.Initial)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.Close)
	initial := ref.KeyPair(channelHex(t, v.Initial))
	client := ref.New(channelHex(t, v.Root), initial, true)
	var message ref.Message
	for range 256 {
		message = client.Send(channelHex(t, v.Alice), bytes.Repeat([]byte{9}, 32))
	}
	forged := ref.SealRecord(message.Secret, channelHex(t, v.ID), 255, 1, 0, message.Header, 1, []byte("credentials"))
	forged[len(forged)-1] ^= 1
	if _, _, _, err := session.AcceptStart(255, forged); !errors.Is(err, ErrChannelAuthentication) {
		t.Fatalf("forged body accepted: %v", err)
	}
	reader, writer, metadata, err := session.AcceptStart(0, channelHex(t, v.Request[0].Encoded))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	t.Cleanup(writer.Close)
	if !bytes.Equal(metadata, channelHex(t, v.Request[0].Plaintext)) {
		t.Fatal("rejected starts changed the authenticated metadata")
	}
}

func TestChannelConcurrentOwnersAndCloseUseTheRustCore(t *testing.T) {
	v := channelVector(t)
	root, id, initial := [32]byte(channelHex(t, v.Root)), [32]byte(channelHex(t, v.ID)), [32]byte(channelHex(t, v.Initial))
	request, response := v.Request, v.Response
	session, err := NewChannelSession(root, id, initial)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.Close)
	forged := channelHex(t, request[0].Encoded)
	forged[len(forged)-1] ^= 1
	if _, _, _, err := session.AcceptStart(0, forged); !errors.Is(err, ErrChannelAuthentication) {
		t.Fatal(err)
	}
	start := channelHex(t, request[0].Encoded)
	reader, writer, metadata, err := session.AcceptStart(0, start)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	t.Cleanup(writer.Close)
	if !bytes.Equal(metadata, channelHex(t, request[0].Plaintext)) {
		t.Fatal("wrong metadata")
	}
	if _, _, _, err := session.AcceptStart(0, channelHex(t, request[0].Encoded)); !errors.Is(err, ErrChannelRecord) {
		t.Fatal(err)
	}
	// Closing the parent concurrently with independent upload/response work must
	// not destroy admitted keys or let a new start through.
	var wait sync.WaitGroup
	wait.Add(3)
	go func() {
		defer wait.Done()
		for _, record := range request[1:] {
			kind, actual, err := reader.Open(channelHex(t, record.Encoded))
			if err != nil || kind != record.Kind || !bytes.Equal(actual, channelHex(t, record.Plaintext)) {
				t.Error("open", err)
			}
		}
		if err := reader.Complete(); err != nil {
			t.Error(err)
		}
	}()
	go func() {
		defer wait.Done()
		var aead cipher.AEAD
		var nonce [12]byte
		for i, record := range response {
			actual, err := writer.Seal(record.Kind, channelHex(t, record.Plaintext))
			if err != nil {
				t.Error("seal", err)
				return
			}
			if i == 0 {
				aead, nonce = channelResponseCipher(t, v, actual)
			}
			prefix := 4
			if i == 0 {
				prefix = 6 + int(binary.BigEndian.Uint16(actual[4:6]))
			}
			recordNonce := nonce
			for j, b := range binary.BigEndian.AppendUint64(nil, uint64(i)) {
				recordNonce[4+j] ^= b
			}
			plain, err := aead.Open(nil, recordNonce[:], actual[prefix:], actual[:prefix])
			expected := append([]byte{record.Kind}, channelHex(t, record.Plaintext)...)
			if err != nil || !bytes.Equal(plain, expected) {
				t.Error("independent response decryption", err)
			}
		}
	}()
	go func() { defer wait.Done(); session.Expire(time.Now()); session.Close(); session.Close() }()
	wait.Wait()
	if _, _, _, err := session.AcceptStart(0, channelHex(t, request[0].Encoded)); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	reader.Close()
	reader.Close()
	writer.Close()
	writer.Close()
	if _, _, err := reader.Open(nil); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if err := reader.Complete(); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if _, err := writer.Seal(1, nil); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestChannelMalformedInputsDoNotExposePlaintextOrReuseFailedWriters(t *testing.T) {
	v := channelVector(t)
	root, id, initial := [32]byte(channelHex(t, v.Root)), [32]byte(channelHex(t, v.ID)), [32]byte(channelHex(t, v.Initial))
	request := v.Request
	session, err := NewChannelSession(root, id, initial)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	for _, input := range [][]byte{nil, {}, {0, 0, 0, 0}, make([]byte, 65537)} {
		if reader, writer, plain, err := session.AcceptStart(0, input); err == nil || reader != nil || writer != nil || plain != nil {
			t.Fatal("invalid start", err)
		}
	}
	reader, writer, _, err := session.AcceptStart(0, channelHex(t, request[0].Encoded))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if _, err := writer.Seal(255, nil); !errors.Is(err, ErrChannelRecord) {
		t.Fatal(err)
	}
	if _, err := writer.Seal(1, nil); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if _, plain, err := reader.Open(nil); err == nil || plain != nil {
		t.Fatal("invalid body", err)
	}
	if err := reader.Complete(); err == nil {
		t.Fatal("accepted missing terminal record")
	}
}

func TestChannelSetupKeyMatchesIndependentX448AndMLKEM(t *testing.T) {
	private, public, err := GenerateChannelKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private[:])
	key := ref.KeyPair(private[:])
	if !bytes.Equal(key.Public[:], public[:]) {
		t.Fatal("setup key pair mismatch")
	}
	_, next, err := GenerateChannelKey()
	if err != nil || next == public {
		t.Fatal("setup key reused", err)
	}
}
