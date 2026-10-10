package reference

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha512"
	"errors"
)

// Independent composite MLDSA65-Ed25519-SHA512 verification with an empty
// application context (draft-ietf-lamps-pq-composite-sigs).

const (
	mldsaPublicKeyBytes   = 1952
	mldsaSignatureBytes   = 3309
	SigningPublicKeyBytes = mldsaPublicKeyBytes + ed25519.PublicKeySize
	SignatureBytes        = mldsaSignatureBytes + ed25519.SignatureSize
	compositeLabel        = "COMPSIG-MLDSA65-Ed25519-SHA512"
)

// VerifySignature requires both component signatures over the composite message representative.
func VerifySignature(public, message, signature []byte) error {
	if len(public) != SigningPublicKeyBytes || len(signature) != SignatureBytes {
		return errors.New("invalid composite key or signature length")
	}
	key, err := mldsa.NewPublicKey(mldsa.MLDSA65(), public[:mldsaPublicKeyBytes])
	if err != nil {
		return err
	}
	digest := sha512.Sum512(message)
	representative := append([]byte("CompositeAlgorithmSignatures2025"+compositeLabel+"\x00"), digest[:]...)
	if err := mldsa.Verify(key, representative, signature[:mldsaSignatureBytes], &mldsa.Options{Context: compositeLabel}); err != nil {
		return err
	}
	if !ed25519.Verify(public[mldsaPublicKeyBytes:], representative, signature[mldsaSignatureBytes:]) {
		return errors.New("invalid Ed25519 component signature")
	}
	return nil
}
