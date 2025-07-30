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
//	crypt, err := async.NewAsyncCrypt()
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

// Crypt represents the main cryptographic operations struct.
// This is a placeholder for future synchronous cryptographic operations.
// For current functionality, use the 'async' package.
type Crypt struct {
}

// NewCrypt creates a new Crypt instance.
// This is currently a placeholder for future synchronous cryptographic operations.
// For post-quantum cryptography, use async.NewAsyncCrypt() instead.
func NewCrypt() *Crypt {
	return &Crypt{}
}

// Version returns the version of the Ouroboros cryptographic library.
// This can be used for compatibility checks and debugging.
func (c *Crypt) Version() string {
	return "1.0.0"
}
