// Package async provides asynchronous cryptographic operations using post-quantum algorithms.
// It implements ML-KEM (Module-Lattice-based Key Encapsulation Mechanism) and ML-DSA (Module-Lattice-based Digital Signature Algorithm)
// for quantum-resistant cryptography.
package async

import (
	"fmt"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// AsyncCrypt represents the main cryptographic operations struct that combines
// key encapsulation mechanisms (KEM) and digital signature algorithms (DSA).
// It holds both private and public keys for ML-KEM and ML-DSA operations.
type AsyncCrypt struct {
	privateKey PrivateKey
	publicKey  PublicKey
}

// NewAsyncCrypt creates a new AsyncCrypt instance with freshly generated key pairs.
// It generates both ML-KEM1024 key pairs for key encapsulation and ML-DSA87 key pairs for digital signatures.
// Returns an error if key generation fails for either algorithm.
func NewAsyncCrypt() (*AsyncCrypt, error) {
	// Generate MLKEM1024 key pair.
	kemScheme := mlkem1024.Scheme()
	kemPub, kemPriv, err := kemScheme.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate MLKEM1024 key pair: %v", err)

	}

	// Generate ML-DSA87 signing key.
	mldsaScheme := mldsa87.Scheme()
	mldsaPub, mldsaPriv, err := mldsaScheme.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-DSA87 private key: %v", err)
	}

	return &AsyncCrypt{
		privateKey: PrivateKey{
			privateKem:  kemPriv,
			privateSign: mldsaPriv,
		},
		publicKey: PublicKey{
			publicKem:  kemPub,
			publicSign: mldsaPub,
		},
	}, nil
}

// GetPublicKey returns a copy of the public key associated with this AsyncCrypt instance.
// This key can be shared publicly and used for encryption and signature verification.
func (ac *AsyncCrypt) GetPublicKey() PublicKey {
	return ac.publicKey
}

// GetPrivateKey returns a copy of the private key associated with this AsyncCrypt instance.
// This key must be kept secure and is used for decryption and signing operations.
func (ac *AsyncCrypt) GetPrivateKey() PrivateKey {
	return ac.privateKey
}

// Encapsulate performs key encapsulation using the ML-KEM algorithm.
// It generates a shared secret and an encapsulated key that can be transmitted to the recipient.
// The recipient can use their private key to decapsulate and recover the same shared secret.
// Returns the shared secret, encapsulated key, and an error if the operation fails.
func (ac *AsyncCrypt) Encapsulate() (sharedSecret, encapsulatedKey []byte, err error) {
	ciphertext, sharedSecret, err := ac.publicKey.publicKem.Scheme().Encapsulate(ac.publicKey.publicKem)
	return sharedSecret, ciphertext, err
}

// Decapsulate recovers the shared secret from an encapsulated key using the ML-KEM private key.
// This is the counterpart to Encapsulate and must be called with the same encapsulated key
// that was generated during encapsulation to recover the identical shared secret.
// Returns the shared secret or an error if decapsulation fails.
func (ac *AsyncCrypt) Decapsulate(encapsulatedKey []byte) ([]byte, error) {
	return ac.privateKey.privateKem.Scheme().Decapsulate(ac.privateKey.privateKem, encapsulatedKey)
}
