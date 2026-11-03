package stogas

import "errors"

// VerificationError preserves the core's fixed reason without parsing human-readable messages.
type VerificationError struct {
	Code    string
	Message string
}

func (err *VerificationError) Error() string { return err.Message }

// TrustRoot is a local offline trust seed. Never construct it from downloaded evidence.
type TrustRoot struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	// RekorPublicKey is the only key that may log this root's key manifests.
	RekorPublicKey string `json:"rekor_public_key"`
	// RekorV2 is where this root's documents count in Rekor v2. Without it, no Rekor v2 entry counts.
	RekorV2 *RekorV2Scope `json:"rekor_v2,omitempty"`
}

// RekorV2Scope is where a root's documents count in Rekor v2.
type RekorV2Scope struct {
	// FirstIndexes gives each log, by checkpoint origin, the first index that counts.
	FirstIndexes map[string]uint64 `json:"first_indexes"`
	// OpenedFrom admits any other log from its first entry if its key's validity in Sigstore's
	// trusted root starts at or after this UTC time, such as 2026-10-31T00:00:00Z.
	OpenedFrom string `json:"opened_from"`
}

// EvidenceOptions selects the environment. A nil Root selects the compiled Stogas authority.
type EvidenceOptions struct {
	Environment string     `json:"environment"`
	Root        *TrustRoot `json:"root,omitempty"`
}

// BootIdentity contains fields returned only after hardware and binding verification.
type BootIdentity struct {
	NodeID               string `json:"node_id"`
	ChipID               string `json:"chip_id"`
	ReportedTCB          string `json:"reported_tcb"`
	BootSHA256           string `json:"boot_sha256"`
	GatewayReleaseID     string `json:"gateway_release_id"`
	SigningPublicKey     string `json:"signing_public_key"`
	HPKEPublicKey        string `json:"hpke_public_key"`
	TLSSPKISHA256        string `json:"tls_spki_sha256"`
	ValidFromUnixMS      int64  `json:"valid_from_unix_ms"`
	ValidUntilUnixMS     int64  `json:"valid_until_unix_ms"`
	IntegratedTimeUnixMS *int64 `json:"integrated_time_unix_ms"`
}

// VerifiedReceipt confirms the metadata, and each side whose digest was given, under a
// hardware-bound boot key. A side left unchecked is signed only as its commitment.
type VerifiedReceipt struct {
	NodeID             string `json:"node_id"`
	BootSHA256         string `json:"boot_sha256"`
	RequestCommitment  string `json:"request_commitment"`
	ResponseCommitment string `json:"response_commitment"`
	RequestVerified    bool   `json:"request_verified"`
	ResponseVerified   bool   `json:"response_verified"`
}

// ContentDigest is the SHA-512 of a request or response in its RFC 8785 form, which a
// receipt commits to under a salt that only the caller receives.
type ContentDigest [64]byte

var (
	// ErrReceiptContent reports content that is not one JSON object without duplicate keys,
	// or a stream event that does not belong to a response.
	ErrReceiptContent = errors.New("content cannot carry a receipt")
	// ErrInexactInteger reports an integer beyond -9007199254740991 to 9007199254740991,
	// which RFC 8785 cannot write exactly.
	ErrInexactInteger = errors.New("content has an integer beyond -9007199254740991 to 9007199254740991")
)

func digestBytes(digest *ContentDigest) []byte {
	if digest == nil {
		return nil
	}
	return digest[:]
}
