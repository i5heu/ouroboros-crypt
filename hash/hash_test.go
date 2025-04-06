package hash_test

import (
	"crypto/sha512"
	"reflect"
	"testing"

	"github.com/i5heu/ouroboros-crypt/hash" // Replace with the actual module path.
)

func TestHashString(t *testing.T) {
	input := "abc"
	expectedHex := "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
	h := hash.HashString(input)
	if got := h.String(); got != expectedHex {
		t.Errorf("HashString(%q) = %q, want %q", input, got, expectedHex)
	}
}

func TestHashBytes(t *testing.T) {
	input := []byte("abc")
	expected := sha512.Sum512(input)
	h := hash.HashBytes(input)
	if h != expected {
		t.Errorf("HashBytes(%q) = %v, want %v", input, h, expected)
	}
}

func TestHashHexadecimal(t *testing.T) {
	expectedHex := "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
	h, err := hash.HashHexadecimal(expectedHex)
	if err != nil {
		t.Fatalf("HashHexadecimal(%q) returned error: %v", expectedHex, err)
	}
	if got := h.String(); got != expectedHex {
		t.Errorf("HashHexadecimal(%q) = %q, want %q", expectedHex, got, expectedHex)
	}

	// Test error on invalid length.
	_, err = hash.HashHexadecimal("abcd")
	if err == nil {
		t.Errorf("HashHexadecimal with invalid length did not return an error")
	}
}

func TestHashHexadecimalInvalidHex(t *testing.T) {
	// "zz" is not valid hexadecimal, so hex.DecodeString should return an error.
	_, err := hash.HashHexadecimal("zz")
	if err == nil {
		t.Error("Expected error for invalid hex string in HashHexadecimal, got nil")
	}
}

func TestEqual(t *testing.T) {
	h1 := hash.HashString("abc")
	h2 := hash.HashString("abc")
	h3 := hash.HashString("def")
	if !h1.Equal(h2) {
		t.Errorf("Expected hashes of %q to be equal", "abc")
	}
	if h1.Equal(h3) {
		t.Errorf("Expected hash of %q and %q to be different", "abc", "def")
	}
}

func TestIsZero(t *testing.T) {
	var zero hash.Hash
	if !zero.IsZero() {
		t.Errorf("Zero hash is not detected as zero")
	}
	nonZero := hash.HashString("abc")
	if nonZero.IsZero() {
		t.Errorf("Non-zero hash detected as zero")
	}
}

func TestMarshalUnmarshalText(t *testing.T) {
	original := hash.HashString("abc")
	marshalled, err := original.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText returned error: %v", err)
	}
	var unmarshalled hash.Hash
	if err := unmarshalled.UnmarshalText(marshalled); err != nil {
		t.Fatalf("UnmarshalText returned error: %v", err)
	}
	if !original.Equal(unmarshalled) {
		t.Errorf("Unmarshalled hash %q does not equal original %q", unmarshalled.String(), original.String())
	}
}

func TestUnmarshalTextInvalid(t *testing.T) {
	var h hash.Hash
	// "zzzz" is not valid hexadecimal.
	err := h.UnmarshalText([]byte("zzzz"))
	if err == nil {
		t.Errorf("Expected error when unmarshaling invalid hex string, got nil")
	}
}

func TestUnmarshalTextInvalidLength(t *testing.T) {
	var h hash.Hash
	// "abcd" is valid hex (decoding to two bytes), but a Hash requires 64 bytes.
	err := h.UnmarshalText([]byte("abcd"))
	if err == nil {
		t.Error("Expected error for hex string of invalid length in UnmarshalText, got nil")
	}
}

func TestBytes(t *testing.T) {
	h := hash.HashString("abc")
	b := h.Bytes()
	if !reflect.DeepEqual(b, h[:]) {
		t.Errorf("Bytes() returned %v, want %v", b, h[:])
	}
}
