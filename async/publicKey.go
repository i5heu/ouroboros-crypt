package async

import (
	"encoding/hex"

	"github.com/i5heu/ouroboros-crypt/hash"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/sign"
)

type PublicKey struct {
	publicKem  kem.PublicKey
	publicSign sign.PublicKey
	hash       *hash.Hash
} 

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

func (p *PublicKey) MarshalBinaryKEM() ([]byte, error) {
	return p.publicKem.MarshalBinary()
}
func (p *PublicKey) MarshalBinarySign() ([]byte, error) {
	return p.publicSign.MarshalBinary()
}

func (p *PublicKey) StringKEM() (string, error) {
	bin, err := p.publicKem.MarshalBinary()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bin), nil
}

func (p *PublicKey) StringSign() (string, error) {
	bin, err := p.publicSign.MarshalBinary()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bin), nil
}

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

func (p *PublicKey) Base64KEM() (string, error) {
	bin, err := p.publicKem.MarshalBinary()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bin), nil
}

func (p *PublicKey) Base64Sign() (string, error) {
	bin, err := p.publicSign.MarshalBinary()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bin), nil
}
