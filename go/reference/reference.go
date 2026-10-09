// Package reference is an independent peer used only by
// conformance tests and fixture generation. It is not a production transport.
package reference

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
)

const Protocol = "stogas.e2ee.pqdr.v1_X25519_MLKEM768_HKDFSHA512_AES256GCM"
const HeaderBytes = 2336
const PublicBytes = 1216

type Keys struct {
	DH     *ecdh.PrivateKey
	KEM    *mlkem.DecapsulationKey768
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
	material := KDF(nil, seed, ":KeyGeneration", 96)
	dh, err := ecdh.X25519().NewPrivateKey(material[:32])
	if err != nil {
		panic(err)
	}
	kem, err := mlkem.NewDecapsulationKey768(material[32:])
	if err != nil {
		panic(err)
	}
	key := &Keys{DH: dh, KEM: kem}
	copy(key.Public[:32], dh.PublicKey().Bytes())
	copy(key.Public[32:], kem.EncapsulationKey().Bytes())
	return key
}
func (k *Keys) Agree(public []byte) []byte {
	remote, err := ecdh.X25519().NewPublicKey(public[:32])
	if err != nil {
		panic(err)
	}
	shared, err := k.DH.ECDH(remote)
	if err != nil {
		panic("non-contributory X25519")
	}
	return shared
}
func Encap(public, seed []byte) (ciphertext, shared []byte) {
	key, err := mlkem.NewEncapsulationKey768(public[32:])
	if err != nil {
		panic(err)
	}
	shared, ciphertext, err = mlkemtest.Encapsulate768(key, seed)
	if err != nil {
		panic(err)
	}
	return
}
func (k *Keys) Decap(ciphertext []byte) []byte {
	shared, err := k.KEM.Decapsulate(ciphertext)
	if err != nil {
		panic(err)
	}
	return shared
}
func GCM(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}

// Nonce is the standard GCM nonce for one outer request or record number.
func Nonce(number uint64) []byte {
	return binary.BigEndian.AppendUint64(make([]byte, 4), number)
}

// Message carries its outer request number, which is also the header nonce.
type Message struct {
	Header, Secret []byte
	Request        uint64
}
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
func Chain(chain []byte) (next, secret []byte) {
	material := KDF(nil, chain, ":Chain", 64)
	return material[:32], material[32:]
}
func (p *Peer) Send(request uint64, seed, randomness []byte) Message {
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
	next, secret := Chain(p.SendChain)
	p.SendChain = next
	p.Sent++
	return Message{GCM(p.SendHeader).Seal(nil, Nonce(request), header, []byte(Protocol)), secret, request}
}
func OpenHeader(key, encoded []byte, request uint64) ([]byte, error) {
	if len(encoded) != HeaderBytes {
		return nil, errors.New("header length")
	}
	return GCM(key).Open(nil, Nonce(request), encoded, []byte(Protocol))
}
func (p *Peer) Receive(message Message) []byte {
	var header []byte
	var err error
	if p.ReceiveHeader != nil {
		header, err = OpenHeader(p.ReceiveHeader, message.Header, message.Request)
	}
	if header == nil || err != nil {
		header, err = OpenHeader(p.NextReceive, message.Header, message.Request)
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
	number := binary.BigEndian.Uint64(header[2312:2320])
	if number < p.Received || number-p.Received > 1<<20 {
		panic("reference counter is out of bounds")
	}
	for p.Received < number {
		p.ReceiveChain, _ = Chain(p.ReceiveChain)
		p.Received++
	}
	next, secret := Chain(p.ReceiveChain)
	p.ReceiveChain = next
	p.Received++
	return secret
}

// RecordKeys is the independent Go model of the one-way record chain.
// The supplied message secret is pseudorandom HKDF output from the ratchet.
type RecordKeys struct {
	chain    []byte
	sequence uint64
}

func NewRecordKeys(secret, id []byte, number uint64, direction byte) *RecordKeys {
	info := append([]byte("stogas.e2ee.record.v1\x00"), id...)
	info = binary.BigEndian.AppendUint64(info, number)
	info = append(info, direction)
	chain, err := hkdf.Expand(sha256.New, secret, string(info), 32)
	if err != nil {
		panic(err)
	}
	return &RecordKeys{chain: chain}
}
func (keys *RecordKeys) Next() (cipher.AEAD, [12]byte) {
	info := binary.BigEndian.AppendUint64([]byte("stogas.e2ee.record-key.v1\x00"), keys.sequence)
	material, err := hkdf.Expand(sha256.New, keys.chain, string(info), 64)
	if err != nil {
		panic(err)
	}
	clear(keys.chain)
	keys.chain = material[:32]
	aead := GCM(material[32:])
	clear(material[32:])
	nonce := [12]byte(Nonce(keys.sequence))
	keys.sequence++
	return aead, nonce
}
func SealRecord(secret, id []byte, number uint64, direction byte, sequence uint64, header []byte, kind byte, content []byte) []byte {
	keys := NewRecordKeys(secret, id, number, direction)
	var aead cipher.AEAD
	var nonce [12]byte
	for i := uint64(0); i <= sequence; i++ {
		aead, nonce = keys.Next()
	}
	prefix := make([]byte, 4)
	if sequence == 0 {
		prefix = binary.BigEndian.AppendUint16(prefix, uint16(len(header)))
		prefix = append(prefix, header...)
	}
	binary.BigEndian.PutUint32(prefix, uint32(len(prefix)+len(content)+17))
	return aead.Seal(prefix, nonce[:], append([]byte{kind}, content...), prefix)
}
