package async

import (
	"testing"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func TestNewPrivateKeyFromBinary_Valid(t *testing.T) {
	// Generate KEM key pair and marshal private key.
	kemScheme := mlkem1024.Scheme()
	_, kemPriv, err := kemScheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate KEM key pair: %v", err)
	}
	kemBytes, err := kemPriv.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal KEM private key: %v", err)
	}

	// Generate signing key and marshal private key.
	signScheme := mldsa87.Scheme()
	_, signPriv, err := signScheme.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}
	signBytes, err := signPriv.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal signing private key: %v", err)
	}

	// Create new PrivateKey from binary data.
	privKey, err := NewPrivateKeyFromBinary(kemBytes, signBytes)
	if err != nil {
		t.Fatalf("NewPrivateKeyFromBinary failed: %v", err)
	}

	// Test MarshalBinaryKEM output.
	marshaledKEM, err := privKey.MarshalBinaryKEM()
	if err != nil {
		t.Fatalf("MarshalBinaryKEM failed: %v", err)
	}
	if len(marshaledKEM) == 0 {
		t.Error("MarshalBinaryKEM returned empty slice")
	}

	// Test MarshalBinarySign output.
	marshaledSign, err := privKey.MarshalBinarySign()
	if err != nil {
		t.Fatalf("MarshalBinarySign failed: %v", err)
	}
	if len(marshaledSign) == 0 {
		t.Error("MarshalBinarySign returned empty slice")
	}
}

func TestNewPrivateKeyFromBinary_InvalidKEM(t *testing.T) {
	// Empty KEM bytes.
	kemBytes := []byte{}

	// Generate valid signing key.
	signScheme := mldsa87.Scheme()
	_, signPriv, err := signScheme.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}
	signBytes, err := signPriv.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal signing private key: %v", err)
	}

	// Expect error due to invalid KEM bytes.
	_, err = NewPrivateKeyFromBinary(kemBytes, signBytes)
	if err == nil {
		t.Error("expected error for invalid KEM bytes, got nil")
	}
}

func TestNewPrivateKeyFromBinary_InvalidSign(t *testing.T) {
	// Generate valid KEM key.
	kemScheme := mlkem1024.Scheme()
	_, kemPriv, err := kemScheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate KEM key pair: %v", err)
	}
	kemBytes, err := kemPriv.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal KEM private key: %v", err)
	}

	// Empty signing bytes.
	signBytes := []byte{}

	// Expect error due to invalid sign bytes.
	_, err = NewPrivateKeyFromBinary(kemBytes, signBytes)
	if err == nil {
		t.Error("expected error for invalid signing bytes, got nil")
	}
}
