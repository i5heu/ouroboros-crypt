package async

import (
	"testing"
)

// Test success scenario for NewAsyncCrypt.
func TestNewAsyncCrypt_Success(t *testing.T) {
	ac, err := NewAsyncCrypt()
	if err != nil {
		t.Fatalf("NewAsyncCrypt returned error: %v", err)
	}
	if ac == nil {
		t.Fatal("NewAsyncCrypt returned nil instance")
	}

	// Check private key fields.
	if ac.privateKey.privateKem == nil {
		t.Error("privateKey.privateKem is nil")
	}
	if ac.privateKey.privateSign == nil {
		t.Error("privateKey.privateSign is nil")
	}

	// Check public key fields.
	if ac.publicKey.publicKem == nil {
		t.Error("publicKey.publicKem is nil")
	}
	if ac.publicKey.publicSign == nil {
		t.Error("publicKey.publicSign is nil")
	}
}
