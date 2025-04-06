package async

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign"
)

// OuroContainer is our custom file structure that holds the version and the two private keys.
type OuroContainer struct {
	Version       string `json:"version"`
	MLKEM1024Priv string `json:"mlkem1024_priv"` // Base64-encoded MLKEM1024 private key
	MLDSA87Priv   string `json:"mldsa87_priv"`   // Base64-encoded ML-DSA87 private key
}

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

func NewAsyncCryptFromFile(filename string) (*AsyncCrypt, error) {
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
