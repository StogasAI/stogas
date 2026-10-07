// Package channeltest is an independent, reference peer used only by
// conformance tests and fixture generation. It is not a production transport.
package channeltest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

const Protocol = "stogas.e2ee.pqdr.v1_X448_MLKEM768_HKDFSHA512_AES256GCM"
const HeaderBytes = 2384
const PublicBytes = 1240

type Keys struct {
	DH     x448.Key
	KEM    *mlkem768.PrivateKey
	Public [PublicBytes]byte
}

func KDF(salt, input []byte, label string, length int) []byte {
	out, err := hkdf.Key(sha512.New, input, salt, Protocol+label, length)
	if err != nil {
		panic(err)
	}
	return out
}
func KeyPair(seed []byte) *Keys {
	material := KDF(nil, seed, ":KeyGeneration", 120)
	key := &Keys{DH: x448.Key(material[:56])}
	public, private := mlkem768.NewKeyFromSeed(material[56:])
	key.KEM = private
	var dh x448.Key
	x448.KeyGen(&dh, &key.DH)
	copy(key.Public[:56], dh[:])
	public.Pack(key.Public[56:])
	return key
}
func (k *Keys) Agree(public []byte) []byte {
	var shared x448.Key
	remote := x448.Key(public[:56])
	if !x448.Shared(&shared, &k.DH, &remote) {
		panic("non-contributory X448")
	}
	return shared[:]
}
func Encap(public, seed []byte) (ciphertext, shared []byte) {
	var key mlkem768.PublicKey
	if err := key.Unpack(public[56:]); err != nil {
		panic(err)
	}
	ciphertext, shared = make([]byte, 1088), make([]byte, 32)
	key.EncapsulateTo(ciphertext, shared, seed)
	return
}
func (k *Keys) Decap(ciphertext []byte) []byte {
	shared := make([]byte, 32)
	k.KEM.DecapsulateTo(shared, ciphertext)
	return shared
}
func GCM(key []byte, nonceBytes int) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCMWithNonceSize(block, nonceBytes)
	if err != nil {
		panic(err)
	}
	return aead
}

type Message struct{ Header, Secret []byte }
type Peer struct {
	Root, SendChain, ReceiveChain                    []byte
	SendHeader, ReceiveHeader, NextSend, NextReceive []byte
	Local                                            *Keys
	Remote, Ciphertext                               []byte
	Sent, Previous, Received                         uint64
}

func New(root []byte, initial *Keys, client bool) *Peer {
	material := KDF(nil, root, ":Initialization", 96)
	p := &Peer{Root: material[:32], NextSend: material[32:64], NextReceive: material[64:]}
	if client {
		p.Remote = append([]byte(nil), initial.Public[:]...)
	} else {
		p.NextSend, p.NextReceive = p.NextReceive, p.NextSend
		p.Local = initial
	}
	return p
}
func (p *Peer) advance(dh, kem []byte) (chain, nextHeader []byte) {
	material := KDF(p.Root, append(dh, kem...), ":Root", 96)
	p.Root = material[:32]
	return material[32:64], material[64:]
}
func Chain(chain []byte) (next, secret, nonce []byte) {
	material := KDF(nil, chain, ":Chain", 80)
	return material[:32], material[32:64], material[64:]
}
func (p *Peer) Send(seed, randomness []byte) Message {
	if p.SendChain == nil {
		p.Local = KeyPair(seed)
		ciphertext, shared := Encap(p.Remote, randomness)
		p.Ciphertext = ciphertext
		p.SendHeader = p.NextSend
		p.SendChain, p.NextSend = p.advance(p.Local.Agree(p.Remote), shared)
		p.Sent = 0
	}
	header := append([]byte(nil), p.Local.Public[:]...)
	header = append(header, p.Ciphertext...)
	header = binary.BigEndian.AppendUint64(header, p.Previous)
	header = binary.BigEndian.AppendUint64(header, p.Sent)
	header = append(header, make([]byte, 8)...)
	next, secret, nonce := Chain(p.SendChain)
	p.SendChain = next
	p.Sent++
	return Message{GCM(p.SendHeader, 16).Seal(append([]byte(nil), nonce...), nonce, header, []byte(Protocol)), secret}
}
func OpenHeader(key, encoded []byte) ([]byte, error) {
	if len(encoded) != HeaderBytes {
		return nil, errors.New("header length")
	}
	return GCM(key, 16).Open(nil, encoded[:16], encoded[16:], []byte(Protocol))
}
func (p *Peer) Receive(message Message) []byte {
	var header []byte
	var err error
	if p.ReceiveHeader != nil {
		header, err = OpenHeader(p.ReceiveHeader, message.Header)
	}
	if header == nil || err != nil {
		header, err = OpenHeader(p.NextReceive, message.Header)
		if err != nil {
			panic(err)
		}
		p.Remote = append([]byte(nil), header[:PublicBytes]...)
		p.ReceiveHeader = p.NextReceive
		p.ReceiveChain, p.NextReceive = p.advance(p.Local.Agree(p.Remote), p.Local.Decap(header[PublicBytes:PublicBytes+1088]))
		p.Previous = p.Sent
		p.SendChain = nil
		p.Received = 0
	}
	number := binary.BigEndian.Uint64(header[2336:2344])
	if number < p.Received || number-p.Received > 1<<20 {
		panic("reference counter is out of bounds")
	}
	for p.Received < number {
		p.ReceiveChain, _, _ = Chain(p.ReceiveChain)
		p.Received++
	}
	next, secret, _ := Chain(p.ReceiveChain)
	p.ReceiveChain = next
	p.Received++
	return secret
}

func RecordMaterial(secret, id []byte, number uint64, direction byte) (cipher.AEAD, []byte) {
	info := append([]byte("stogas.e2ee.record.v1\x00"), id...)
	info = binary.BigEndian.AppendUint64(info, number)
	info = append(info, direction)
	material, err := hkdf.Expand(sha256.New, secret, string(info), 44)
	if err != nil {
		panic(err)
	}
	return GCM(material[:32], 12), material[32:]
}
func SealRecord(secret, id []byte, number uint64, direction byte, sequence uint64, header []byte, kind byte, content []byte) []byte {
	aead, base := RecordMaterial(secret, id, number, direction)
	prefix := make([]byte, 4)
	if sequence == 0 {
		prefix = binary.BigEndian.AppendUint16(prefix, uint16(len(header)))
		prefix = append(prefix, header...)
	}
	binary.BigEndian.PutUint32(prefix, uint32(len(prefix)+len(content)+17))
	nonce := append([]byte(nil), base...)
	for i, b := range binary.BigEndian.AppendUint64(nil, sequence) {
		nonce[4+i] ^= b
	}
	return aead.Seal(prefix, nonce, append([]byte{kind}, content...), prefix)
}
