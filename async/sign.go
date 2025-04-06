package async

import (
	"crypto"
	"crypto/rand"
)

func (ac *AsyncCrypt) Sign(data []byte) ([]byte, error) {
	// Pass crypto.Hash(0) as the signer options instead of nil.
	signature, err := ac.privateKey.privateSign.Sign(rand.Reader, data, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func (ac *AsyncCrypt) Verify(data, signature []byte) bool {
	return ac.publicKey.publicSign.Scheme().Verify(ac.publicKey.publicSign, data, signature, nil)
}
