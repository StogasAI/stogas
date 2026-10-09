package reference

import (
	"crypto/hmac"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// SetupPrefixBytes is the server setup prefix before its possession confirmation.
const SetupPrefixBytes = 6 + 32 + 4 + 1120 + PublicBytes

// Setup is an independent client hello. Go HPKE derives the session root that
// the Rust server keeps private; no test needs a server-side key export.
type Setup struct {
	Hello []byte
	key   hpke.PrivateKey
}

func NewSetup(environment byte, seed []byte) (*Setup, error) {
	key, err := hpke.MLKEM768X25519().NewPrivateKey(seed)
	if err != nil {
		return nil, err
	}
	hello := append([]byte("STGS\x01\x01"), environment)
	challenge := sha256.Sum256(seed)
	hello = append(hello, challenge[:]...)
	return &Setup{Hello: append(hello, key.PublicKey().Bytes()...), key: key}, nil
}

// Session is one completed setup. Client returns a fresh reference initiator.
type Session struct {
	ID          [32]byte
	IdleSeconds uint32
	Transcript  [32]byte
	Root        [32]byte
	Initial     [PublicBytes]byte
}

func (s *Session) Client() *Peer {
	return New(s.Root[:], &Keys{Public: s.Initial}, true)
}

// Complete checks the transcript and possession confirmation of a server prefix.
func (s *Setup) Complete(prefix []byte, bootHash [32]byte) (*Session, error) {
	if len(prefix) != SetupPrefixBytes+32 || string(prefix[:6]) != "STGS\x01\x02" {
		return nil, errors.New("invalid setup prefix")
	}
	transcript := sha256.New()
	transcript.Write([]byte("stogas.e2ee.transcript.v1\x00"))
	transcript.Write(s.Hello)
	transcript.Write(prefix[:SetupPrefixBytes])
	transcript.Write(bootHash[:])
	session := &Session{ID: [32]byte(prefix[6:38]), IdleSeconds: binary.BigEndian.Uint32(prefix[38:42]), Transcript: [32]byte(transcript.Sum(nil)), Initial: [PublicBytes]byte(prefix[1162:SetupPrefixBytes])}
	info := sha256.Sum256(s.Hello)
	recipient, err := hpke.NewRecipient(prefix[42:1162], s.key, hpke.HKDFSHA256(), hpke.ExportOnly(), append([]byte("stogas.e2ee.setup.v1\x00"), info[:]...))
	if err != nil {
		return nil, err
	}
	confirmation, err := recipient.Export("stogas.e2ee.confirmation.v1\x00"+string(session.Transcript[:]), 32)
	if err != nil || !hmac.Equal(confirmation, prefix[SetupPrefixBytes:]) {
		return nil, errors.New("incorrect possession confirmation")
	}
	root, err := recipient.Export("stogas.e2ee.root.v1\x00"+string(session.Transcript[:]), 32)
	if err != nil {
		return nil, err
	}
	session.Root = [32]byte(root)
	return session, nil
}
