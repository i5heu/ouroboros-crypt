package hash

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
)

// SHA-512 hash represented as a 64-byte array.
type Hash [64]byte

// HashBytes computes the Hash of the given data.
func HashBytes(data []byte) Hash {
	return sha512.Sum512(data)
}

// HashHexadecimal parses a hexadecimal string and returns a Hash.
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

// HashString computes the Hash of the given string.
func HashString(s string) Hash {
	return HashBytes([]byte(s))
}

// Equal compares two hashes for equality.
func (h Hash) Equal(other Hash) bool {
	return h == other
}

// String returns the hexadecimal string representation of the hash.
func (h Hash) String() string {
	return hex.EncodeToString(h[:])
}

// Bytes returns the underlying byte slice of the hash.
func (h Hash) Bytes() []byte {
	return h[:]
}

// IsZero checks if the hash is a zero value (i.e. all bytes are zero).
func (h Hash) IsZero() bool {
	var zero Hash
	return h == zero
}

// MarshalText implements the encoding.TextMarshaler interface.
// It returns the hash as a hex string.
func (h Hash) MarshalText() ([]byte, error) {
	return []byte(h.String()), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
// It expects a hexadecimal string representation of the hash.
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
