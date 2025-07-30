package async

import (
	"encoding/base64"
	"encoding/hex"

	"github.com/i5heu/ouroboros-crypt/hash"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// PublicKey represents a composite public key that contains both ML-KEM and ML-DSA public keys.
// It combines key encapsulation mechanism (KEM) and digital signature algorithm (DSA) public keys
// for comprehensive post-quantum cryptographic operations. It also maintains a cached hash value
// for efficient comparison and identification.
type PublicKey struct {
	publicKem  kem.PublicKey  // ML-KEM1024 public key for key encapsulation
	publicSign sign.PublicKey // ML-DSA87 public key for digital signature verification
	hash       *hash.Hash     // Cached hash of the public key for efficient comparison
}

// NewPublicKeyFromBinary creates a new PublicKey instance from binary-encoded key data.
// It takes separate byte slices for the ML-KEM and ML-DSA public keys and reconstructs
// the public key objects from their binary representations.
// Returns an error if either key cannot be unmarshaled from the provided binary data.
func NewPublicKeyFromBinary(kemBytes, signBytes []byte) (*PublicKey, error) {
	// Import the necessary schemes at package level if not already imported
	kemPub, err := mlkem1024.Scheme().UnmarshalBinaryPublicKey(kemBytes)
	if err != nil {
		return nil, err
	}

	signPub, err := mldsa87.Scheme().UnmarshalBinaryPublicKey(signBytes)
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		publicKem:  kemPub,
		publicSign: signPub,
	}, nil
}

// NewPublicKeyFromHex creates a new PublicKey instance from hexadecimal-encoded key data.
// It takes separate hex strings for the ML-KEM and ML-DSA public keys and reconstructs
// the public key objects from their binary representations.
// Returns an error if either string is not valid hexadecimal or if key reconstruction fails.
func NewPublicKeyFromHex(kemHex, signHex string) (*PublicKey, error) {
	kemBytes, err := hex.DecodeString(kemHex)
	if err != nil {
		return nil, err
	}

	signBytes, err := hex.DecodeString(signHex)
	if err != nil {
		return nil, err
	}

	return NewPublicKeyFromBinary(kemBytes, signBytes)
}

// NewPublicKeyFromBase64 creates a new PublicKey instance from base64-encoded key data.
// It takes separate base64 strings for the ML-KEM and ML-DSA public keys and reconstructs
// the public key objects from their binary representations.
// Returns an error if either string is not valid base64 or if key reconstruction fails.
func NewPublicKeyFromBase64(kemBase64, signBase64 string) (*PublicKey, error) {
	kemBytes, err := base64.StdEncoding.DecodeString(kemBase64)
	if err != nil {
		return nil, err
	}

	signBytes, err := base64.StdEncoding.DecodeString(signBase64)
	if err != nil {
		return nil, err
	}

	return NewPublicKeyFromBinary(kemBytes, signBytes)
}

// Hash computes and returns a hash.Hash object representing the hash of the PublicKey.
// It returns an error if the hashing process fails.
func (p *PublicKey) Hash() (hash.Hash, error) {
	if p.hash == nil {
		bin, err := p.publicKem.MarshalBinary()
		if err != nil {
			return hash.Hash{}, err
		}
		hashTmp := hash.HashBytes(bin)
		p.hash = &hashTmp
	}
	tmp := *p.hash
	return tmp, nil
}

// MarshalBinaryKEM serializes the PublicKey into a binary format suitable for use with
// key encapsulation mechanisms (KEM). It returns the encoded byte slice or an error
// if the serialization fails.
func (p *PublicKey) MarshalBinaryKEM() ([]byte, error) {
	return p.publicKem.MarshalBinary()
}

// MarshalBinarySign serializes the PublicKey into a binary format suitable for signing operations.
// It returns the serialized byte slice and an error if the serialization fails.
func (p *PublicKey) MarshalBinarySign() ([]byte, error) {
	return p.publicSign.MarshalBinary()
}

// StringKEM returns a string representation of the public key suitable for use in
// key encapsulation mechanisms (KEM). It returns the encoded string and an error
// if the encoding fails.
func (p *PublicKey) StringKEM() (string, error) {
	bin, err := p.publicKem.MarshalBinary()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bin), nil
}

// StringSign returns a hexadecimal string representation of the ML-DSA public key.
// It marshals the digital signature public key to binary format and encodes it as a hex string.
// Returns the encoded string and an error if the marshaling fails.
func (p *PublicKey) StringSign() (string, error) {
	bin, err := p.publicSign.MarshalBinary()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bin), nil
}

// Equal compares this PublicKey with another PublicKey for equality.
// It performs a comprehensive comparison of both ML-KEM and ML-DSA public key components.
// Returns true if both keys are identical, false otherwise.
// Handles nil pointer cases safely.
func (p *PublicKey) Equal(other *PublicKey) bool {
	if p == nil || other == nil {
		return false
	}
	if p.publicKem == nil || other.publicKem == nil {
		return false
	}
	if p.publicSign == nil || other.publicSign == nil {
		return false
	}
	return p.publicKem.Equal(other.publicKem) && p.publicSign.Equal(other.publicSign)
}

// Base64KEM returns a hexadecimal string representation of the ML-KEM public key.
// Note: Despite the "Base64" name, this method returns hex-encoded data for backward compatibility.
// It marshals the key encapsulation mechanism public key to binary format and encodes it as hexadecimal.
// Returns the encoded string and an error if the marshaling fails.
func (p *PublicKey) Base64KEM() (string, error) {
	bin, err := p.publicKem.MarshalBinary()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bin), nil
}

// Base64Sign returns a hexadecimal string representation of the ML-DSA public key.
// Note: Despite the "Base64" name, this method returns hex-encoded data for backward compatibility.
// It marshals the digital signature public key to binary format and encodes it as hexadecimal.
// Returns the encoded string and an error if the marshaling fails.
func (p *PublicKey) Base64Sign() (string, error) {
	bin, err := p.publicSign.MarshalBinary()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bin), nil
}

// ToBase64KEM returns a proper base64-encoded string representation of the ML-KEM public key.
// It marshals the key encapsulation mechanism public key to binary format and encodes it as base64.
// Returns the encoded string and an error if the marshaling fails.
func (p *PublicKey) ToBase64KEM() (string, error) {
	bin, err := p.publicKem.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bin), nil
}

// ToBase64Sign returns a proper base64-encoded string representation of the ML-DSA public key.
// It marshals the digital signature public key to binary format and encodes it as base64.
// Returns the encoded string and an error if the marshaling fails.
func (p *PublicKey) ToBase64Sign() (string, error) {
	bin, err := p.publicSign.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bin), nil
}

// Verify verifies a digital signature against the provided data using the ML-DSA public key.
// It checks that the signature was created by the corresponding private key for the given data.
// Returns true if the signature is valid, false otherwise.
func (p *PublicKey) Verify(data, signature []byte) bool {
	return p.publicSign.Scheme().Verify(p.publicSign, data, signature, nil)
}

// Encapsulate performs key encapsulation using the ML-KEM public key.
// It generates a shared secret and an encapsulated key. The shared secret should be used
// for symmetric encryption, while the encapsulated key should be transmitted to the recipient.
// Returns the shared secret, encapsulated key, and an error if the operation fails.
func (p *PublicKey) Encapsulate() (sharedSecret, encapsulatedKey []byte, err error) {
	ciphertext, sharedSecret, err := p.publicKem.Scheme().Encapsulate(p.publicKem)
	return sharedSecret, ciphertext, err
}
