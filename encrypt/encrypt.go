// Package encrypt provides encryption and decryption of arbitrary binary data
// using ML-KEM1024 for key encapsulation and AES-GCM for symmetric encryption.
package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/i5heu/ouroboros-crypt/keys"
)

// Encryptor holds public and private keys for convenient encryption/decryption.
type Encryptor struct {
	PublicKey  *keys.PublicKey
	PrivateKey *keys.PrivateKey
}

// NewEncryptor initializes an Encryptor with the given public and/or private key.
func NewEncryptor(pub *keys.PublicKey, priv *keys.PrivateKey) *Encryptor {
	return &Encryptor{PublicKey: pub, PrivateKey: priv}
}

// Encrypt encrypts data using the Encryptor's public key.
func (e *Encryptor) Encrypt(data []byte) (*EncryptResult, error) {
	if e.PublicKey == nil {
		return nil, errors.New("Encryptor: public key is nil")
	}
	return Encrypt(data, e.PublicKey)
}

// Decrypt decrypts data using the Encryptor's private key.
func (e *Encryptor) Decrypt(enc *EncryptResult) ([]byte, error) {
	if e.PrivateKey == nil {
		return nil, errors.New("Encryptor: private key is nil")
	}
	return Decrypt(enc, e.PrivateKey)
}

// EncryptResult contains the encrypted data and the encapsulated secret.
type EncryptResult struct {
	Ciphertext      []byte // Encrypted data
	EncapsulatedKey []byte // ML-KEM encapsulated secret
	Nonce           []byte // AES-GCM nonce
}

// Encrypt encrypts arbitrary binary data using the recipient's ML-KEM1024 public key.
// It returns the encrypted data, encapsulated secret, and nonce.
func Encrypt(data []byte, pub *keys.PublicKey) (*EncryptResult, error) {
	if pub == nil {
		return nil, errors.New("public key cannot be nil")
	}

	// 1. Encapsulate a shared secret using ML-KEM1024
	sharedSecret, encapsulatedKey, err := pub.Encapsulate()
	if err != nil {
		return nil, err
	}

	// 2. Use the shared secret as the AES-256-GCM key
	if len(sharedSecret) < 32 {
		return nil, errors.New("shared secret too short for AES-256")
	}
	key := sharedSecret[:32]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)

	return &EncryptResult{
		Ciphertext:      ciphertext,
		EncapsulatedKey: encapsulatedKey,
		Nonce:           nonce,
	}, nil
}

// Decrypt decrypts the encrypted data using the recipient's ML-KEM1024 private key.
// It takes the ciphertext, encapsulated secret, and nonce, and returns the original data.
func Decrypt(enc *EncryptResult, priv *keys.PrivateKey) ([]byte, error) {
	if enc == nil {
		return nil, errors.New("encrypt result cannot be nil")
	}
	if priv == nil {
		return nil, errors.New("private key cannot be nil")
	}

	// 1. Decapsulate the shared secret using ML-KEM1024 private key
	sharedSecret, err := priv.Decapsulate(enc.EncapsulatedKey)
	if err != nil {
		return nil, err
	}
	if len(sharedSecret) < 32 {
		return nil, errors.New("shared secret too short for AES-256")
	}
	key := sharedSecret[:32]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(enc.Nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce size")
	}

	plaintext, err := gcm.Open(nil, enc.Nonce, enc.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}
	return plaintext, nil
}
