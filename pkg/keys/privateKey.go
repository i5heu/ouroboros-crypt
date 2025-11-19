package keys

import (
	"encoding/base64"
	"encoding/hex"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// PrivateKey represents a composite private key that contains both ML-KEM and ML-DSA private keys.
// It combines key encapsulation mechanism (KEM) and digital signature algorithm (DSA) private keys
// for comprehensive post-quantum cryptographic operations.
type PrivateKey struct {
	privateKem  kem.PrivateKey  // ML-KEM1024 private key for key encapsulation
	privateSign sign.PrivateKey // ML-DSA87 private key for digital signatures
}

// NewPrivateKeyFromBinary creates a new PrivateKey instance from binary-encoded key data.
// It takes separate byte slices for the ML-KEM and ML-DSA private keys and reconstructs
// the private key objects from their binary representations.
// Returns an error if either key cannot be unmarshaled from the provided binary data.
func NewPrivateKeyFromBinary(kemBytes, signBytes []byte) (*PrivateKey, error) {
	kemPriv, err := mlkem1024.Scheme().UnmarshalBinaryPrivateKey(kemBytes)
	if err != nil {
		return nil, err
	}

	signPriv, err := mldsa87.Scheme().UnmarshalBinaryPrivateKey(signBytes)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{
		privateKem:  kemPriv,
		privateSign: signPriv,
	}, nil
}

// NewPrivateKeyFromHex creates a new PrivateKey instance from hexadecimal-encoded key data.
// It takes separate hex strings for the ML-KEM and ML-DSA private keys and reconstructs
// the private key objects from their binary representations.
// Returns an error if either string is not valid hexadecimal or if key reconstruction fails.
func NewPrivateKeyFromHex(kemHex, signHex string) (*PrivateKey, error) {
	kemBytes, err := hex.DecodeString(kemHex)
	if err != nil {
		return nil, err
	}

	signBytes, err := hex.DecodeString(signHex)
	if err != nil {
		return nil, err
	}

	return NewPrivateKeyFromBinary(kemBytes, signBytes)
}

// NewPrivateKeyFromBase64 creates a new PrivateKey instance from base64-encoded key data.
// It takes separate base64 strings for the ML-KEM and ML-DSA private keys and reconstructs
// the private key objects from their binary representations.
// Returns an error if either string is not valid base64 or if key reconstruction fails.
func NewPrivateKeyFromBase64(kemBase64, signBase64 string) (*PrivateKey, error) {
	kemBytes, err := base64.StdEncoding.DecodeString(kemBase64)
	if err != nil {
		return nil, err
	}

	signBytes, err := base64.StdEncoding.DecodeString(signBase64)
	if err != nil {
		return nil, err
	}

	return NewPrivateKeyFromBinary(kemBytes, signBytes)
}

// MarshalBinaryKEM serializes the ML-KEM private key component to binary format.
// This method extracts only the key encapsulation mechanism private key and
// returns its binary representation. Returns an error if the marshaling fails.
func (p *PrivateKey) MarshalBinaryKEM() ([]byte, error) {
	return p.privateKem.MarshalBinary()
}

// MarshalBinarySign serializes the ML-DSA private key component to binary format.
// This method extracts only the digital signature algorithm private key and
// returns its binary representation. Returns an error if the marshaling fails.
func (p *PrivateKey) MarshalBinarySign() ([]byte, error) {
	return p.privateSign.MarshalBinary()
}

// Public returns the corresponding PublicKey for this PrivateKey.
// It extracts the public key components from both the ML-KEM and ML-DSA private keys.
// This is useful for sharing the public key with other parties for encryption and signature verification.
func (p *PrivateKey) Public() PublicKey {
	return PublicKey{
		publicKem:  p.privateKem.Public(),
		publicSign: p.privateSign.Public().(sign.PublicKey),
	}
}

// Equal compares this PrivateKey with another PrivateKey for equality.
// It performs a comprehensive comparison of both ML-KEM and ML-DSA private key components.
// Returns true if both keys are identical, false otherwise.
// Handles nil pointer cases safely.
func (p *PrivateKey) Equal(other *PrivateKey) bool {
	if p == nil || other == nil {
		return false
	}
	if p.privateKem == nil || other.privateKem == nil {
		return false
	}
	if p.privateSign == nil || other.privateSign == nil {
		return false
	}
	return p.privateKem.Equal(other.privateKem) && p.privateSign.Equal(other.privateSign)
}

// StringKEM returns a hexadecimal string representation of the ML-KEM private key.
// Returns the encoded string and an error if the marshaling fails.
func (p *PrivateKey) StringKEM() (string, error) {
	bin, err := p.privateKem.MarshalBinary()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bin), nil
}

// StringSign returns a hexadecimal string representation of the ML-DSA private key.
// Returns the encoded string and an error if the marshaling fails.
func (p *PrivateKey) StringSign() (string, error) {
	bin, err := p.privateSign.MarshalBinary()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bin), nil
}

// ToBase64KEM returns a base64-encoded string representation of the ML-KEM private key.
// Returns the encoded string and an error if the marshaling fails.
func (p *PrivateKey) ToBase64KEM() (string, error) {
	bin, err := p.privateKem.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bin), nil
}

// ToBase64Sign returns a base64-encoded string representation of the ML-DSA private key.
// Returns the encoded string and an error if the marshaling fails.
func (p *PrivateKey) ToBase64Sign() (string, error) {
	bin, err := p.privateSign.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bin), nil
}

// Decapsulate recovers the shared secret from an encapsulated key using the ML-KEM private key.
// This is a public method for use by other packages.
func (p *PrivateKey) Decapsulate(encapsulatedKey []byte) ([]byte, error) {
	return p.privateKem.Scheme().Decapsulate(p.privateKem, encapsulatedKey)
}
