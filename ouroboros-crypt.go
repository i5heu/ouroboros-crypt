// Package crypt provides cryptographic operations using post-quantum cryptography.
// It implements the Ouroboros cryptographic library with support for ML-KEM and ML-DSA algorithms.
//
// The library provides both synchronous and asynchronous cryptographic operations:
//   - The 'async' package contains post-quantum cryptographic primitives
//   - The 'hash' package provides SHA-512 hashing functionality
//
// Example usage:
//
//	import "github.com/i5heu/ouroboros-crypt/async"
//
//	// Create a new cryptographic instance
//	crypt, err := keys.NewAsyncCrypt()
//	if err != nil {
//	    panic(err)
//	}
//
//	// Sign some data
//	data := []byte("Hello, post-quantum world!")
//	signature, err := crypt.Sign(data)
//	if err != nil {
//	    panic(err)
//	}
//
//	// Verify the signature
//	valid := crypt.Verify(data, signature)
//	fmt.Printf("Signature valid: %v\n", valid)
package crypt

import (
	"github.com/i5heu/ouroboros-crypt/encrypt"
	"github.com/i5heu/ouroboros-crypt/hash"
	"github.com/i5heu/ouroboros-crypt/keys"
)

// Crypt represents the main cryptographic operations struct.
// This struct now exposes synchronous encrypt and hash operations.
type Crypt struct {
}

// NewCrypt creates a new Crypt instance.
// This is currently a placeholder for future synchronous cryptographic operations.
// For post-quantum cryptography, use keys.NewAsyncCrypt() instead.
func NewCrypt() *Crypt {
	return &Crypt{}
}

// Version returns the version of the Ouroboros cryptographic library.
// This can be used for compatibility checks and debugging.
func (c *Crypt) Version() string {
	return "1.0.0"
}

// Encrypt encrypts data using the recipient's ML-KEM1024 public key.
func (c *Crypt) Encrypt(data []byte, pub *keys.PublicKey) (*encrypt.EncryptResult, error) {
	return encrypt.Encrypt(data, pub)
}

// Decrypt decrypts data using the recipient's ML-KEM1024 private key.
func (c *Crypt) Decrypt(enc *encrypt.EncryptResult, priv *keys.PrivateKey) ([]byte, error) {
	return encrypt.Decrypt(enc, priv)
}

// HashBytes computes the SHA-512 hash of the given byte slice.
func (c *Crypt) HashBytes(data []byte) hash.Hash {
	return hash.HashBytes(data)
}
