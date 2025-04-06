package async

import (
	"fmt"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

type AsyncCrypt struct {
	privateKey PrivateKey
	publicKey  PublicKey
}

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
