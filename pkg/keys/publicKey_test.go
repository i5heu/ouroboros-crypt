package keys

import (
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// getTestPublicKey returns a PublicKey built from a generated KEM and signing key.
func getTestPublicKey(t *testing.T) *PublicKey {
	kemScheme := mlkem1024.Scheme()
	kemPub, _, err := kemScheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate KEM key pair: %v", err)
	}
	signScheme := mldsa87.Scheme()
	signPub, _, err := signScheme.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}
	return &PublicKey{
		publicKem:  kemPub,
		publicSign: signPub,
		// hash is nil initially; will be computed on first call.
	}
}

func TestPublicKey_Hash(t *testing.T) {
	pk := getTestPublicKey(t)
	h1, err := pk.Hash()
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}
	// second call should return the same cached hash
	h2, err := pk.Hash()
	if err != nil {
		t.Fatalf("Hash() error on second call: %v", err)
	}
	if h1 != h2 {
		t.Error("Hash() returned different values on subsequent calls")
	}
}

func TestPublicKey_StringAndBase64(t *testing.T) {
	pk := getTestPublicKey(t)
	kemStr, err := pk.StringKEM()
	if err != nil {
		t.Fatalf("StringKEM() error: %v", err)
	}
	signStr, err := pk.StringSign()
	if err != nil {
		t.Fatalf("StringSign() error: %v", err)
	}
	// Validate hex string conversion
	if _, err := hex.DecodeString(kemStr); err != nil {
		t.Error("StringKEM() returned invalid hex string")
	}
	if _, err := hex.DecodeString(signStr); err != nil {
		t.Error("StringSign() returned invalid hex string")
	}
	base64KEM, err := pk.Base64KEM()
	if err != nil {
		t.Fatalf("Base64KEM() error: %v", err)
	}
	base64Sign, err := pk.Base64Sign()
	if err != nil {
		t.Fatalf("Base64Sign() error: %v", err)
	}
	// Note: Both Base64 methods use hex.EncodeToString so outputs should match.
	if base64KEM != kemStr {
		t.Error("Base64KEM() output does not match expected hex string")
	}
	if base64Sign != signStr {
		t.Error("Base64Sign() output does not match expected hex string")
	}
}

func TestPublicKey_Equal(t *testing.T) {
	pk1 := getTestPublicKey(t)
	// A key must be equal to itself.
	if !pk1.Equal(pk1) {
		t.Error("PublicKey is not equal to itself")
	}
	// Generate a different PublicKey for negative testing.
	pk2 := getTestPublicKey(t)
	if pk1.Equal(pk2) {
		t.Error("Different PublicKeys are considered equal")
	}
}
