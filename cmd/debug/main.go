package main

import (
	"fmt"
	"log"

	"github.com/i5heu/ouroboros-crypt/encrypt"
	"github.com/i5heu/ouroboros-crypt/keys"
)

func main() {
	ac, err := keys.NewAsyncCrypt()
	if err != nil {
		log.Fatal(err)
	}

	testData := []byte("Hello, World!")
	fmt.Printf("Original data: %s\n", testData)

	pubKey := ac.GetPublicKey()
	result, err := encrypt.Encrypt(testData, &pubKey)
	if err != nil {
		log.Fatal("Encryption failed:", err)
	}

	fmt.Printf("Ciphertext length: %d\n", len(result.Ciphertext))
	fmt.Printf("EncapsulatedKey length: %d\n", len(result.EncapsulatedKey))
	fmt.Printf("Nonce length: %d\n", len(result.Nonce))

	privKey := ac.GetPrivateKey()
	decrypted, err := encrypt.Decrypt(result, &privKey)
	if err != nil {
		log.Fatal("Decryption failed:", err)
	}

	fmt.Printf("Decrypted data: %s\n", decrypted)
}
