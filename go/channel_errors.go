//go:build stogas_gateway

package verifier

import "errors"

// ChannelPublicKeyBytes is the setup-bound X25519 and ML-KEM-768 public key width.
const ChannelPublicKeyBytes = 32 + 1184

var (
	ErrChannelRecord         = errors.New("invalid encrypted record")
	ErrChannelAuthentication = errors.New("encrypted record authentication failed")
	ErrChannelLimit          = errors.New("encrypted record usage limit reached")
	ErrChannelTruncated      = errors.New("encrypted stream ended without completion")
	ErrChannelPending        = errors.New("encrypted session awaits request-start acknowledgements")
	ErrChannelCrypto         = errors.New("encrypted session cryptography failed")
)

// ChannelSetup retains all secrets in Session. Quote Transcript with the chosen
// environment and boot hash before publishing the session or ResponsePrefix.
// Append the evidence length/body to ResponsePrefix. Close Session if quoting or
// publication fails; the public output bytes need no secret erasure.
type ChannelSetup struct {
	Session        *ChannelSession
	ID             [32]byte
	Transcript     [32]byte
	ResponsePrefix []byte
}
