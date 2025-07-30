// Package hash provides SHA-512 cryptographic hashing functionality.
// It defines a Hash type as a 64-byte array and provides utilities for creating,
// parsing, and manipulating SHA-512 hashes with support for various encodings.
package hash

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
)

// Hash represents a SHA-512 hash as a 64-byte array.
// This type provides a safe and efficient way to work with SHA-512 hash values
// and includes methods for encoding, comparison, and text marshaling.
type Hash [64]byte

// HashBytes computes the SHA-512 hash of the given byte slice.
// It returns a Hash value containing the 64-byte SHA-512 digest.
func HashBytes(data []byte) Hash {
	return sha512.Sum512(data)
}

// HashHexadecimal parses a hexadecimal string and returns the corresponding Hash.
// The input string must represent exactly 64 bytes (128 hexadecimal characters).
// Returns an error if the string is not valid hexadecimal or has incorrect length.
func HashHexadecimal(s string) (Hash, error) {
	var h Hash
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return h, err
	}
	if len(decoded) != len(h) {
		return h, fmt.Errorf("invalid length: expected %d bytes, got %d", len(h), len(decoded))
	}
	copy(h[:], decoded)
	return h, nil
}

// HashString computes the SHA-512 hash of the given string.
// It converts the string to bytes and computes its SHA-512 hash.
func HashString(s string) Hash {
	return HashBytes([]byte(s))
}

// Equal compares two Hash values for equality.
// Returns true if both hashes contain identical byte values.
func (h Hash) Equal(other Hash) bool {
	return h == other
}

// String returns the hexadecimal string representation of the hash.
// The returned string is 128 characters long (64 bytes * 2 hex chars per byte).
func (h Hash) String() string {
	return hex.EncodeToString(h[:])
}

// Bytes returns the underlying byte slice representation of the hash.
// This provides access to the raw 64-byte hash value.
func (h Hash) Bytes() []byte {
	return h[:]
}

// IsZero checks if the hash is a zero value (all bytes are zero).
// This is useful for detecting uninitialized hash values.
func (h Hash) IsZero() bool {
	var zero Hash
	return h == zero
}

// MarshalText implements the encoding.TextMarshaler interface.
// It returns the hash as a hexadecimal string encoded as bytes.
// This enables automatic encoding when used with JSON, XML, and other text-based formats.
func (h Hash) MarshalText() ([]byte, error) {
	return []byte(h.String()), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
// It expects a hexadecimal string representation of the hash (128 characters).
// This enables automatic decoding when used with JSON, XML, and other text-based formats.
// Returns an error if the input is not valid hexadecimal or has incorrect length.
func (h *Hash) UnmarshalText(text []byte) error {
	decoded, err := hex.DecodeString(string(text))
	if err != nil {
		return err
	}
	if len(decoded) != len(h) {
		return fmt.Errorf("invalid length: expected %d bytes, got %d", len(h), len(decoded))
	}
	copy(h[:], decoded)
	return nil
}
