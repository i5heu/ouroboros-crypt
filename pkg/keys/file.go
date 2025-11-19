package keys

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign"
)

// OuroContainer represents the file structure for persisting AsyncCrypt keys to disk.
// It contains versioning information and base64-encoded private keys for both
// ML-KEM1024 (key encapsulation) and ML-DSA87 (digital signature) algorithms.
// This structure ensures forward compatibility and secure key storage.
type OuroContainer struct {
	Version       string `json:"version"`        // Version of the container format
	MLKEM1024Priv string `json:"mlkem1024_priv"` // Base64-encoded MLKEM1024 private key
	MLDSA87Priv   string `json:"mldsa87_priv"`   // Base64-encoded ML-DSA87 private key
}

// SaveToFile persists the AsyncCrypt private keys to a JSON file.
// The keys are base64-encoded and stored in a versioned container format.
// The file is created with restricted permissions (0600) to protect the private keys.
// Returns an error if key marshaling, JSON encoding, or file writing fails.
func (ac *AsyncCrypt) SaveToFile(filename string) error {
	// Create the OuroContainer with the version and keys

	kemPriv, err := ac.privateKey.privateKem.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal MLKEM1024 private key: %v", err)
	}

	signPriv, err := ac.privateKey.privateSign.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal ML-DSA87 private key: %v", err)
	}
	container := OuroContainer{
		Version:       "1.0",
		MLKEM1024Priv: base64.StdEncoding.EncodeToString(kemPriv),
		MLDSA87Priv:   base64.StdEncoding.EncodeToString(signPriv),
	}

	// Marshal the container to JSON
	data, err := json.Marshal(container)
	if err != nil {
		return fmt.Errorf("failed to marshal container to JSON: %v", err)
	}

	// Write the JSON data to the file
	err = os.WriteFile(filename, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write to file: %v", err)
	}

	return nil
}

// NewCryptFromFile creates a new AsyncCrypt instance by loading private keys from a JSON file.
// It reads the file, decodes the JSON container, and reconstructs the private keys
// from their base64-encoded representations. The corresponding public keys are derived
// from the private keys. Returns an error if file reading, JSON decoding, base64 decoding,
// or key reconstruction fails.
func NewCryptFromFile(filename string) (*AsyncCrypt, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	var container OuroContainer
	if err := json.Unmarshal(data, &container); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	kemPrivBytes, err := base64.StdEncoding.DecodeString(container.MLKEM1024Priv)
	if err != nil {
		return nil, fmt.Errorf("failed to decode MLKEM1024 private key: %v", err)
	}

	mldsaPrivBytes, err := base64.StdEncoding.DecodeString(container.MLDSA87Priv)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ML-DSA87 private key: %v", err)
	}

	pk, err := NewPrivateKeyFromBinary(kemPrivBytes, mldsaPrivBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key from binary: %v", err)
	}

	return &AsyncCrypt{
		privateKey: *pk,
		publicKey: PublicKey{
			publicKem:  pk.privateKem.Public(),
			publicSign: pk.privateSign.Public().(sign.PublicKey),
		},
	}, nil
}
