package encrypt

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/i5heu/ouroboros-crypt/keys"
)

func generateKeyPair(t *testing.T) (*keys.PublicKey, *keys.PrivateKey) {
	ac, err := keys.NewAsyncCrypt()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	pub := ac.GetPublicKey()
	priv := ac.GetPrivateKey()
	return &pub, &priv
}

func TestEncryptDecrypt_Success(t *testing.T) {
	pub, priv := generateKeyPair(t)
	enc := NewEncryptor(pub, priv)
	data := []byte("hello world")

	result, err := enc.Encrypt(data)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := enc.Decrypt(result)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(data, decrypted) {
		t.Errorf("decrypted data does not match original")
	}
}

func TestEncryptor_Encrypt_NoPublicKey(t *testing.T) {
	enc := NewEncryptor(nil, nil)
	_, err := enc.Encrypt([]byte("test"))
	if err == nil {
		t.Error("expected error when public key is nil")
	}
}

func TestEncryptor_Decrypt_NoPrivateKey(t *testing.T) {
	pub, _ := generateKeyPair(t)
	enc := NewEncryptor(pub, nil)
	result, _ := Encrypt([]byte("test"), pub)
	_, err := enc.Decrypt(result)
	if err == nil {
		t.Error("expected error when private key is nil")
	}
}

func TestEncrypt_NilPublicKey(t *testing.T) {
	_, err := Encrypt([]byte("test"), nil)
	if err == nil {
		t.Error("expected error when public key is nil")
	}
}

func TestDecrypt_NilEncryptResult(t *testing.T) {
	_, priv := generateKeyPair(t)
	_, err := Decrypt(nil, priv)
	if err == nil {
		t.Error("expected error when encrypt result is nil")
	}
}

func TestDecrypt_NilPrivateKey(t *testing.T) {
	pub, _ := generateKeyPair(t)
	result, _ := Encrypt([]byte("test"), pub)
	_, err := Decrypt(result, nil)
	if err == nil {
		t.Error("expected error when private key is nil")
	}
}

func TestDecrypt_InvalidEncapsulatedKey(t *testing.T) {
	pub, priv := generateKeyPair(t)
	result, _ := Encrypt([]byte("test"), pub)
	result.EncapsulatedKey = []byte("invalid")
	_, err := Decrypt(result, priv)
	if err == nil {
		t.Error("expected error for invalid encapsulated key")
	}
}

func TestDecrypt_InvalidNonceSize(t *testing.T) {
	pub, priv := generateKeyPair(t)
	result, _ := Encrypt([]byte("test"), pub)
	result.Nonce = []byte("short")
	_, err := Decrypt(result, priv)
	if err == nil {
		t.Error("expected error for invalid nonce size")
	}
}

func TestDecrypt_InvalidCiphertext(t *testing.T) {
	pub, priv := generateKeyPair(t)
	result, _ := Encrypt([]byte("test"), pub)
	result.Ciphertext = []byte("invalid")
	_, err := Decrypt(result, priv)
	if err == nil {
		t.Error("expected error for invalid ciphertext")
	}
}

// TestBasicEncryptDecrypt tests the basic encrypt-decrypt cycle
func TestBasicEncryptDecrypt(t *testing.T) {
	// Generate key pair
	ac, err := keys.NewAsyncCrypt()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	testData := []byte("Hello, World! This is a test message.")

	// Encrypt
	pubKey := ac.GetPublicKey()
	result, err := Encrypt(testData, &pubKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify result structure
	if result == nil {
		t.Fatal("Encryption result is nil")
	}
	if len(result.Ciphertext) == 0 {
		t.Fatal("Ciphertext is empty")
	}
	if len(result.EncapsulatedKey) == 0 {
		t.Fatal("Encapsulated key is empty")
	}
	if len(result.Nonce) == 0 {
		t.Fatal("Nonce is empty")
	}

	// Decrypt
	privKey := ac.GetPrivateKey()
	decrypted, err := Decrypt(result, &privKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify the decrypted data matches the original
	if !bytes.Equal(testData, decrypted) {
		t.Fatalf("Decrypted data doesn't match original.\nOriginal:  %s\nDecrypted: %s", testData, decrypted)
	}
}

// TestEmptyData tests encryption and decryption of empty data
func TestEmptyData(t *testing.T) {
	ac, err := keys.NewAsyncCrypt()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	testData := []byte{}

	pubKey := ac.GetPublicKey()
	result, err := Encrypt(testData, &pubKey)
	if err != nil {
		t.Fatalf("Encryption of empty data failed: %v", err)
	}

	privKey := ac.GetPrivateKey()
	decrypted, err := Decrypt(result, &privKey)
	if err != nil {
		t.Fatalf("Decryption of empty data failed: %v", err)
	}

	if !bytes.Equal(testData, decrypted) {
		t.Fatalf("Decrypted empty data doesn't match original")
	}
}

// TestLargeData tests encryption and decryption of large data
func TestLargeData(t *testing.T) {
	ac, err := keys.NewAsyncCrypt()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create 1MB of random data
	testData := make([]byte, 1024*1024)
	_, err = rand.Read(testData)
	if err != nil {
		t.Fatalf("Failed to generate random test data: %v", err)
	}

	pubKey := ac.GetPublicKey()
	result, err := Encrypt(testData, &pubKey)
	if err != nil {
		t.Fatalf("Encryption of large data failed: %v", err)
	}

	privKey := ac.GetPrivateKey()
	decrypted, err := Decrypt(result, &privKey)
	if err != nil {
		t.Fatalf("Decryption of large data failed: %v", err)
	}

	if !bytes.Equal(testData, decrypted) {
		t.Fatalf("Decrypted large data doesn't match original")
	}
}

// TestMultipleEncryptions tests that multiple encryptions of the same data produce different results
func TestMultipleEncryptions(t *testing.T) {
	ac, err := keys.NewAsyncCrypt()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	testData := []byte("Same message encrypted multiple times")

	pubKey := ac.GetPublicKey()
	privKey := ac.GetPrivateKey()

	// Encrypt the same data multiple times
	result1, err := Encrypt(testData, &pubKey)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	result2, err := Encrypt(testData, &pubKey)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Ciphertexts should be different (due to random nonces and fresh KEM encapsulation)
	if bytes.Equal(result1.Ciphertext, result2.Ciphertext) {
		t.Fatal("Multiple encryptions of the same data produced identical ciphertexts")
	}

	// Nonces should be different
	if bytes.Equal(result1.Nonce, result2.Nonce) {
		t.Fatal("Multiple encryptions produced identical nonces")
	}

	// Encapsulated keys should be different (each KEM operation generates fresh keys)
	if bytes.Equal(result1.EncapsulatedKey, result2.EncapsulatedKey) {
		t.Fatal("Multiple encryptions produced identical encapsulated keys")
	}

	// Both should decrypt to the same original data
	decrypted1, err := Decrypt(result1, &privKey)
	if err != nil {
		t.Fatalf("Decryption of first result failed: %v", err)
	}

	decrypted2, err := Decrypt(result2, &privKey)
	if err != nil {
		t.Fatalf("Decryption of second result failed: %v", err)
	}

	if !bytes.Equal(testData, decrypted1) {
		t.Fatal("First decryption doesn't match original")
	}

	if !bytes.Equal(testData, decrypted2) {
		t.Fatal("Second decryption doesn't match original")
	}
}

// TestWrongPrivateKey tests that decryption fails with the wrong private key
func TestWrongPrivateKey(t *testing.T) {
	// Generate two different key pairs
	ac1, err := keys.NewAsyncCrypt()
	if err != nil {
		t.Fatalf("Failed to generate first key pair: %v", err)
	}

	ac2, err := keys.NewAsyncCrypt()
	if err != nil {
		t.Fatalf("Failed to generate second key pair: %v", err)
	}

	testData := []byte("This should only decrypt with the correct key")

	// Encrypt with first public key
	pubKey1 := ac1.GetPublicKey()
	result, err := Encrypt(testData, &pubKey1)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Try to decrypt with wrong private key - this should fail
	privKey2 := ac2.GetPrivateKey()
	_, err = Decrypt(result, &privKey2)
	if err == nil {
		t.Fatal("Decryption with wrong private key should have failed")
	}
}

// TestCorruptedCiphertext tests behavior with corrupted ciphertext
func TestCorruptedCiphertext(t *testing.T) {
	ac, err := keys.NewAsyncCrypt()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	testData := []byte("This message will be corrupted")

	pubKey := ac.GetPublicKey()
	result, err := Encrypt(testData, &pubKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Corrupt the ciphertext
	if len(result.Ciphertext) > 0 {
		result.Ciphertext[0] ^= 0xFF
	}

	// Decryption should fail
	privKey := ac.GetPrivateKey()
	_, err = Decrypt(result, &privKey)
	if err == nil {
		t.Fatal("Decryption of corrupted ciphertext should have failed")
	}
}

// TestCorruptedNonce tests behavior with corrupted nonce
func TestCorruptedNonce(t *testing.T) {
	ac, err := keys.NewAsyncCrypt()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	testData := []byte("This message will have corrupted nonce")

	pubKey := ac.GetPublicKey()
	result, err := Encrypt(testData, &pubKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Corrupt the nonce
	if len(result.Nonce) > 0 {
		result.Nonce[0] ^= 0xFF
	}

	// Decryption should fail
	privKey := ac.GetPrivateKey()
	_, err = Decrypt(result, &privKey)
	if err == nil {
		t.Fatal("Decryption with corrupted nonce should have failed")
	}
}

// TestCorruptedEncapsulatedKey tests behavior with corrupted encapsulated key
func TestCorruptedEncapsulatedKey(t *testing.T) {
	ac, err := keys.NewAsyncCrypt()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	testData := []byte("This message will have corrupted encapsulated key")

	pubKey := ac.GetPublicKey()
	result, err := Encrypt(testData, &pubKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Corrupt the encapsulated key
	if len(result.EncapsulatedKey) > 0 {
		result.EncapsulatedKey[0] ^= 0xFF
	}

	// Decryption should fail during decapsulation
	privKey := ac.GetPrivateKey()
	_, err = Decrypt(result, &privKey)
	if err == nil {
		t.Fatal("Decryption with corrupted encapsulated key should have failed")
	}
}

// TestInvalidNonceSize tests behavior with invalid nonce size
func TestInvalidNonceSize(t *testing.T) {
	ac, err := keys.NewAsyncCrypt()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	testData := []byte("This message will have invalid nonce size")

	pubKey := ac.GetPublicKey()
	result, err := Encrypt(testData, &pubKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Modify nonce size to be invalid
	result.Nonce = result.Nonce[:len(result.Nonce)-1] // Truncate nonce

	privKey := ac.GetPrivateKey()
	_, err = Decrypt(result, &privKey)
	if err == nil {
		t.Fatal("Decryption with invalid nonce size should have failed")
	}

	expectedError := "invalid nonce size"
	if err.Error() != expectedError {
		t.Fatalf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestNilInputs tests behavior with nil inputs
func TestNilInputs(t *testing.T) {
	ac, err := keys.NewAsyncCrypt()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test encryption with nil public key
	_, err = Encrypt([]byte("test"), nil)
	if err == nil {
		t.Fatal("Encryption with nil public key should have failed")
	}

	// Test decryption with nil private key
	result := &EncryptResult{
		Ciphertext:      []byte("dummy"),
		EncapsulatedKey: []byte("dummy"),
		Nonce:           []byte("dummy"),
	}
	_, err = Decrypt(result, nil)
	if err == nil {
		t.Fatal("Decryption with nil private key should have failed")
	}

	// Test decryption with nil EncryptResult
	privKey := ac.GetPrivateKey()
	_, err = Decrypt(nil, &privKey)
	if err == nil {
		t.Fatal("Decryption with nil EncryptResult should have failed")
	}
}

// TestConcurrentEncryption tests that encryption is safe for concurrent use
func TestConcurrentEncryption(t *testing.T) {
	ac, err := keys.NewAsyncCrypt()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	pubKey := ac.GetPublicKey()
	privKey := ac.GetPrivateKey()

	const numGoroutines = 10
	const numIterations = 10

	errors := make(chan error, numGoroutines*numIterations)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			for j := 0; j < numIterations; j++ {
				testData := []byte("Concurrent test data from goroutine " + string(rune(goroutineID+'0')))

				result, err := Encrypt(testData, &pubKey)
				if err != nil {
					errors <- err
					return
				}

				decrypted, err := Decrypt(result, &privKey)
				if err != nil {
					errors <- err
					return
				}

				if !bytes.Equal(testData, decrypted) {
					errors <- err
					return
				}
			}
			errors <- nil
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		if err := <-errors; err != nil {
			t.Fatalf("Concurrent encryption test failed: %v", err)
		}
	}
}

// BenchmarkEncrypt benchmarks the encryption operation
func BenchmarkEncrypt(b *testing.B) {
	ac, err := keys.NewAsyncCrypt()
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	testData := make([]byte, 1024) // 1KB test data
	_, err = rand.Read(testData)
	if err != nil {
		b.Fatalf("Failed to generate random test data: %v", err)
	}

	pubKey := ac.GetPublicKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(testData, &pubKey)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

// BenchmarkDecrypt benchmarks the decryption operation
func BenchmarkDecrypt(b *testing.B) {
	ac, err := keys.NewAsyncCrypt()
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	testData := make([]byte, 1024) // 1KB test data
	_, err = rand.Read(testData)
	if err != nil {
		b.Fatalf("Failed to generate random test data: %v", err)
	}

	pubKey := ac.GetPublicKey()
	result, err := Encrypt(testData, &pubKey)
	if err != nil {
		b.Fatalf("Encryption failed: %v", err)
	}

	privKey := ac.GetPrivateKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Decrypt(result, &privKey)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}
