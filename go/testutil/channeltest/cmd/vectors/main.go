// Generate independent protocol vectors with Go and CIRCL, without loading Rust.
package main

import (
	"bytes"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	ref "github.com/StogasAI/verifier/go/testutil/channeltest"
)

func hx(b []byte) string       { return hex.EncodeToString(b) }
func filled(value byte) []byte { return bytes.Repeat([]byte{value}, 32) }
func write(dir, name string, value any) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), append(encoded, '\n'), 0644); err != nil {
		panic(err)
	}
}
func record(secret, id []byte, number uint64, direction byte, sequence uint64, header []byte, kind byte, content []byte) map[string]any {
	return map[string]any{"kind": kind, "plaintext_hex": hx(content), "encoded_hex": hx(ref.SealRecord(secret, id, number, direction, sequence, header, kind, content))}
}
func main() {
	out := flag.String("out", "../tests/fixtures", "fixture output directory")
	flag.Parse()
	root, id, initial := filled(5), filled(2), ref.KeyPair(filled(3))
	peers := []*ref.Peer{ref.New(root, initial, true), ref.New(root, initial, false)}
	var messages []map[string]any
	var first ref.Message
	var firstResponse ref.Message
	var rootAfterRequest []byte
	counter := uint64(0)
	random := func() []byte {
		input := binary.BigEndian.AppendUint64([]byte{17}, counter)
		counter++
		digest := sha256.Sum256(input)
		return digest[:]
	}
	for turn, count := range []int{3, 1, 17, 2, 1, 8, 2, 3} {
		side := turn % 2
		for n := 0; n < count; n++ {
			var seed, randomness []byte
			if n == 0 {
				seed, randomness = random(), random()
			}
			message := peers[side].Send(seed, randomness)
			if !bytes.Equal(peers[1-side].Receive(message), message.Secret) {
				panic("reference disagreement")
			}
			messages = append(messages, map[string]any{"side": side, "seed_hex": hx(seed), "randomness_hex": hx(randomness), "header_hex": hx(message.Header), "secret_hex": hx(message.Secret)})
			if turn == 0 && n == 0 {
				first = message
				rootAfterRequest = append([]byte(nil), peers[0].Root...)
			}
			if turn == 1 && n == 0 {
				firstResponse = message
			}
		}
	}
	write(*out, "channel-ratchet.json", map[string]any{"description": "Independent Go/CIRCL X448 + full ML-KEM-768 PQ2HE transcript; Stogas KDF and header encoding.", "root_hex": hx(root), "initial_seed_hex": hx(filled(3)), "initial_public_hex": hx(initial.Public[:]), "messages": messages})
	request := []map[string]any{
		record(first.Secret, id, 0, 1, 0, first.Header, 1, []byte("credentials")),
		record(first.Secret, id, 0, 1, 1, nil, 2, []byte("request body")),
		record(first.Secret, id, 0, 1, 2, nil, 3, nil),
	}
	response := []map[string]any{
		record(firstResponse.Secret, id, 0, 2, 0, firstResponse.Header, 4, nil),
		record(firstResponse.Secret, id, 0, 2, 1, nil, 1, []byte("status=200")),
		record(firstResponse.Secret, id, 0, 2, 2, nil, 2, []byte("response body")),
		record(firstResponse.Secret, id, 0, 2, 3, nil, 3, nil),
	}
	seed := sha256.Sum256(binary.BigEndian.AppendUint64([]byte{17}, 0))
	write(*out, "channel-exchange.json", map[string]any{"description": "Independent Go/CIRCL request and response records. Server runtime responses use fresh entropy and are independently decrypted by the Go binding test.", "root_hex": hx(root), "session_id_hex": hx(id), "initial_private_hex": hx(filled(3)), "alice_seed_hex": hx(seed[:]), "after_request_root_hex": hx(rootAfterRequest), "request_number": 0, "request": request, "response": response})
	codec(*out, first.Header)
	setup(*out, initial)
}
func codec(out string, header []byte) {
	root, id := make([]byte, 32), make([]byte, 32)
	for i := range root {
		root[i] = byte(i)
		id[i] = byte(i + 32)
	}
	var streams []map[string]any
	for _, number := range []uint64{0, 1152921504606847042} {
		for _, direction := range []byte{1, 2} {
			kinds := []byte{1, 2, 3}
			contents := [][]byte{[]byte(`{"method":"POST","path":"/v1/chat/completions"}`), {0, 255, 10, '{', '}'}, nil}
			if direction == 2 {
				kinds = []byte{4, 1, 2, 4, 3}
				contents = [][]byte{nil, []byte(`{"status":200}`), []byte("data: {\"ok\":true}\n\n"), nil, nil}
			}
			var records []map[string]any
			for i, kind := range kinds {
				records = append(records, record(root, id, number, direction, uint64(i), header, kind, contents[i]))
			}
			streams = append(streams, map[string]any{"number": fmt.Sprint(number), "direction": direction, "records": records})
		}
	}
	var invalid []map[string]any
	for _, c := range []struct {
		dir, kind byte
		body      []byte
	}{{1, 1, nil}, {1, 2, nil}, {1, 4, nil}, {1, 3, nil}, {2, 1, nil}, {2, 4, []byte{0}}} {
		invalid = append(invalid, map[string]any{"direction": c.dir, "encoded_hex": hx(ref.SealRecord(root, id, 0, c.dir, 0, header, c.kind, c.body))})
	}
	write(out, "channel-records.json", map[string]any{"description": "Independent Go HKDF-Expand-SHA256 and AES-256-GCM record vectors with a fixed encrypted ratchet header; root_hex is the supplied message secret.", "root_hex": hx(root), "session_id_hex": hx(id), "header_hex": hx(header), "streams": streams, "invalid_firsts": invalid})
}
func setup(out string, initial *ref.Keys) {
	seed, challenge := make([]byte, 32), make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
		challenge[i] = byte(i + 64)
	}
	private, err := hpke.MLKEM768X25519().NewPrivateKey(seed)
	if err != nil {
		panic(err)
	}
	hello := append([]byte("STGS\x01\x01\x01"), challenge...)
	hello = append(hello, private.PublicKey().Bytes()...)
	hh := sha256.Sum256(hello)
	enc, sender, err := hpke.NewSender(private.PublicKey(), hpke.HKDFSHA256(), hpke.ExportOnly(), append([]byte("stogas.e2ee.setup.v1\x00"), hh[:]...))
	if err != nil {
		panic(err)
	}
	prefix := append([]byte("STGS\x01\x02"), filled(2)...)
	prefix = binary.BigEndian.AppendUint32(prefix, 600)
	prefix = append(prefix, enc...)
	prefix = append(prefix, initial.Public[:]...)
	boot := []byte(`{"fixture":"synthetic boot record"}`)
	inclusion := []byte(`{"fixture":"synthetic inclusion"}`)
	bh := sha256.Sum256(boot)
	transcript := sha256.New()
	transcript.Write([]byte("stogas.e2ee.transcript.v1\x00"))
	transcript.Write(hello)
	transcript.Write(prefix)
	transcript.Write(bh[:])
	th := transcript.Sum(nil)
	root, err := sender.Export("stogas.e2ee.root.v1\x00"+string(th), 32)
	if err != nil {
		panic(err)
	}
	confirmation, err := sender.Export("stogas.e2ee.confirmation.v1\x00"+string(th), 32)
	if err != nil {
		panic(err)
	}
	leaf := sha512.New()
	leaf.Write([]byte{0})
	leaf.Write([]byte("stogas.e2ee-session.v1\x00"))
	leaf.Write([]byte{1})
	leaf.Write(bh[:])
	leaf.Write(th)
	batch := sha512.New()
	batch.Write([]byte("stogas.quote-batch.v1\x00"))
	batch.Write([]byte{0, 1})
	batch.Write(leaf.Sum(nil))
	evidence := make([]byte, 1184)
	binary.LittleEndian.PutUint32(evidence, 3)
	binary.LittleEndian.PutUint32(evidence[0x34:], 1)
	copy(evidence[0x50:0x90], batch.Sum(nil))
	evidence = append(evidence, 0, 4, 0, 1, 0, 0)
	evidence = binary.BigEndian.AppendUint32(evidence, uint32(len(boot)))
	evidence = append(evidence, boot...)
	evidence = binary.BigEndian.AppendUint32(evidence, uint32(len(inclusion)))
	evidence = append(evidence, inclusion...)
	response := append(prefix, confirmation...)
	response = binary.BigEndian.AppendUint32(response, uint32(len(evidence)))
	response = append(response, evidence...)
	write(out, "channel-setup.json", map[string]any{"description": "Go HPKE X-Wing setup with synthetic, unsigned SNP report for transcript framing tests only.", "seed_hex": hx(seed), "hello_hex": hx(hello), "response_hex": hx(response), "root_hex": hx(root), "initial_private_hex": hx(filled(3)), "initial_public_hex": hx(initial.Public[:])})
}
