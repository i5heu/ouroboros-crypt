# ouroboros-crypt

Ouroboros Crypt is a post-quantum cryptography library for Go, supporting ML-KEM and ML-DSA algorithms. It provides easy-to-use APIs for key management, encryption/decryption, and SHA-512 hashing.

## Features

- Asynchronous post-quantum key generation and management
- ML-KEM1024 encryption and decryption
- SHA-512 hashing utilities
- Save/load key pairs to/from files

## Installation

```bash
go get github.com/i5heu/ouroboros-crypt
```

## Usage


### Key Generation and Saving

```go
import "github.com/i5heu/ouroboros-crypt/keys"

// Generate a new key pair
ac, err := keys.NewAsyncCrypt()
if err != nil {
    panic(err)
}

// Save keys to a file
err = ac.SaveToFile("mykeys.key")
if err != nil {
    panic(err)
}

// Load keys from a file
acLoaded, err := keys.NewCryptFromFile("mykeys.key")
if err != nil {
    panic(err)
}
```

### Usage with Crypt

You can use the `Crypt` struct for direct encryption, decryption, and hashing. It wraps key management and provides a simple API.

#### 1. Initialize Crypt and Encrypt/Decrypt

```go
import (
    "github.com/i5heu/ouroboros-crypt"
)

// Create a new Crypt instance (generates new keys)
crypt := crypt.New()

// Encrypt some data using the internal public key
data := []byte("hello Ouroboros!")
encResult, err := crypt.Encrypt(data, crypt.Keys.GetPublicKey())
if err != nil {
    panic(err)
}

// Decrypt using the internal private key
decrypted, err := crypt.Decrypt(encResult, crypt.Keys.GetPrivateKey())
if err != nil {
    panic(err)
}
fmt.Printf("Decrypted: %s\n", decrypted)
```

#### 2. Load Crypt from file and use for encryption/decryption

```go
import (
    "github.com/i5heu/ouroboros-crypt"
)

crypt, err := crypt.NewFromFile("mykeys.key")
if err != nil {
    panic(err)
}

data := []byte("secure message")
encResult, err := crypt.Encrypt(data, crypt.Keys.GetPublicKey())
if err != nil {
    panic(err)
}

decrypted, err := crypt.Decrypt(encResult, crypt.Keys.GetPrivateKey())
if err != nil {
    panic(err)
}
fmt.Printf("Decrypted: %s\n", decrypted)
```

> **Note:** You can use an initialized `Crypt` directly for encryption and decryption, without manually creating encryptors or extracting keys. This simplifies usage for most applications.

### Hashing

```go
import "github.com/i5heu/ouroboros-crypt/hash"

// Hash a string
h := hash.HashString("abc")
fmt.Println(h.String()) // hex string

// Hash bytes
h2 := hash.HashBytes([]byte("abc"))
fmt.Printf("%x\n", h2)
```

## Testing

Run all tests:

```bash
go test ./...
```

## License
OuroborosDB (c) 2025 Mia Heidenstedt and contributors

SPDX-License-Identifier: AGPL-3.0