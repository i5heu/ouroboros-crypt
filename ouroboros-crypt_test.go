// ouroboros-crypt_test.go
package crypt

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/i5heu/ouroboros-crypt/keys"
)

func TestNew(t *testing.T) {
	c := New()
	if c == nil {
		t.Fatal("New() returned nil")
	}
	if c.Keys == nil {
		t.Error("Keys not initialized")
	}
	if c.Encryptor == nil {
		t.Error("Encryptor not initialized")
	}
}

func TestNewFromFile(t *testing.T) {
	// Generate a key and save to temp file
	ac, err := keys.NewAsyncCrypt()
	if err != nil {
		t.Fatal(err)
	}
	file, err := ioutil.TempFile("", "crypt_test_*.key")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())
	if err := ac.SaveToFile(file.Name()); err != nil {
		t.Fatalf("Failed to save key: %v", err)
	}
	c, err := NewFromFile(file.Name())
	if err != nil {
		t.Fatalf("NewFromFile failed: %v", err)
	}
	if c == nil {
		t.Error("NewFromFile returned nil")
	}
}

func TestVersion(t *testing.T) {
	c := New()
	ver := c.Version()
	if ver != "1.0.0" {
		t.Errorf("Version() = %s, want 1.0.0", ver)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	c := New()
	data := []byte("test data")
	enc, err := c.Encrypt(data)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	dec, err := c.Decrypt(enc)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if string(dec) != string(data) {
		t.Errorf("Decrypt = %s, want %s", dec, data)
	}
}

func TestHashBytes(t *testing.T) {
	c := New()
	data := []byte("hello world")
	h := c.HashBytes(data)
	// Check that the hash output matches expected SHA-512 length
	hashBytes := h.Bytes()
	if len(hashBytes) != 64 {
		t.Errorf("Hash length = %d, want 64", len(hashBytes))
	}
}
