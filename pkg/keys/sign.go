package keys

import (
	"crypto"
	"crypto/rand"
)

// Sign creates a digital signature for the provided data using the ML-DSA87 private key.
// It uses the private signing key to generate a cryptographically secure signature
// that can be verified using the corresponding public key.
// Returns the signature as a byte slice or an error if the signing operation fails.
func (ac *AsyncCrypt) Sign(data []byte) ([]byte, error) {
	// Pass crypto.Hash(0) as the signer options instead of nil.
	signature, err := ac.privateKey.privateSign.Sign(rand.Reader, data, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// Verify checks the validity of a digital signature against the provided data.
// It uses the ML-DSA87 public key to verify that the signature was created
// by the corresponding private key for the given data.
// Returns true if the signature is valid, false otherwise.
func (ac *AsyncCrypt) Verify(data, signature []byte) bool {
	return ac.publicKey.publicSign.Scheme().Verify(ac.publicKey.publicSign, data, signature, nil)
}
