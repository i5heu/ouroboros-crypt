package async

import "testing"

func TestSaveToFile(t *testing.T) {
	dir := t.TempDir()

	ac, err := NewAsyncCrypt()
	if err != nil {
		t.Fatalf("Failed to create AsyncCrypt: %v", err)
	}

	err = ac.SaveToFile(dir + "/test_asynccrypt")
	if err != nil {
		t.Fatalf("Failed to save AsyncCrypt to file: %v", err)
	}

	acLoaded, err := NewAsyncCryptFromFile(dir + "/test_asynccrypt")
	if err != nil {
		t.Fatalf("Failed to load AsyncCrypt from file: %v", err)
	}

	if acLoaded == nil {
		t.Fatal("Loaded AsyncCrypt is nil")
	}
	if ac.privateKey.privateKem == nil || acLoaded.privateKey.privateKem == nil {
		t.Fatal("Private key is nil")
	}
	if !ac.privateKey.privateKem.Equal(acLoaded.privateKey.privateKem) {
		t.Fatal("Private Kem keys do not match")
	}
	if ac.privateKey.privateSign == nil || acLoaded.privateKey.privateSign == nil {
		t.Fatal("Private Sign signing key is nil")
	}
	if !ac.privateKey.privateSign.Equal(acLoaded.privateKey.privateSign) {
		t.Fatal("Private signing keys do not match")
	}
	if ac.publicKey.publicKem == nil || acLoaded.publicKey.publicKem == nil {
		t.Fatal("Public Kem key is nil")
	}
	if !ac.publicKey.publicKem.Equal(acLoaded.publicKey.publicKem) {
		t.Fatal("Public Kem keys do not match")
	}
	if ac.publicKey.publicSign == nil || acLoaded.publicKey.publicSign == nil {
		t.Fatal("Public signing key is nil")
	}
	if !ac.publicKey.publicSign.Equal(acLoaded.publicKey.publicSign) {
		t.Fatal("Public signing keys do not match")
	}
}
