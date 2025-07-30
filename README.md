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

### Encrypt and Decrypt

```go
import (
    "github.com/i5heu/ouroboros-crypt/encrypt"
    "github.com/i5heu/ouroboros-crypt/keys"
)

// Generate/load keys as above
pub := acLoaded.GetPublicKey()
priv := acLoaded.GetPrivateKey()

enc := encrypt.NewEncryptor(&pub, &priv)
data := []byte("hello world")

// Encrypt
result, err := enc.Encrypt(data)
if err != nil {
    panic(err)
}

// Decrypt
decrypted, err := enc.Decrypt(result)
if err != nil {
    panic(err)
}
```

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