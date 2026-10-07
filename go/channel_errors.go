package verifier

import "errors"

// ChannelPublicKeyBytes is the setup-bound X448 and ML-KEM-768 public key width.
const ChannelPublicKeyBytes = 56 + 1184

var (
	ErrChannelRecord         = errors.New("invalid encrypted record")
	ErrChannelAuthentication = errors.New("encrypted record authentication failed")
	ErrChannelLimit          = errors.New("encrypted record usage limit reached")
	ErrChannelTruncated      = errors.New("encrypted stream ended without completion")
	ErrChannelPending        = errors.New("encrypted session awaits request-start acknowledgements")
	ErrChannelCrypto         = errors.New("encrypted session cryptography failed")
)
