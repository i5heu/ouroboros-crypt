package async

import (
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

type PrivateKey struct {
	privateKem  kem.PrivateKey
	privateSign sign.PrivateKey
}

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

func (p *PrivateKey) MarshalBinaryKEM() ([]byte, error) {
	return p.privateKem.MarshalBinary()
}
func (p *PrivateKey) MarshalBinarySign() ([]byte, error) {
	return p.privateSign.MarshalBinary()
}
