# Enigma.Cryptography.DataEncryption

Enigma.Cryptography.DataEncryption is a .NET library based on `Enigma.Cryptography`.

It provides services for data encryption and decryption.

## Pbkdf2DataEncryptionService

Encryption/decryption service with PBKDF2 algorithm.

### Encryption process

- A block cipher service is initialized with the specified cipher in GCM mode.
- A random 16-bytes salt and a random 12-bytes nonce are generated.
- A 32-bytes key is generated with PBKDF2 algorithm.
- The header is written to the output stream.
- The input stream is encrypted into the output stream with the key and nonce.
- The key is cleared from memory.

### Decryption process

- The header is read from the input stream.
- A 32-bytes key is generated with PBKDF2 algorithm.
- A block cipher service is initialized with the cipher in GCM mode.
- The input stream is decrypted into the output stream with the key and nonce.

### Data structure

| Name            | Length (bytes) | Description                                                             |
|-----------------|----------------|-------------------------------------------------------------------------|
| Identifier      | 2              | Fixed value `[0xec, 0xde]` that identifies encryption with this library |
| Encryption type | 1              | Fixed value `0x01` that identifies encryption with PBKDF2               |
| Version         | 1              | Current version: `0x01`                                                 |
| Cipher          | 1              | Cipher identifier (see table below)                                     |
| Nonce           | 12             | Random nonce for encryption with GCM mode                               |
| Salt            | 16             | Random salt for PBKDF2                                                  |
| Iterations      | 4 (Int32)      | Number of iterations for PBKDF2                                         |
| Encrypted data  | (dynamic)      | Encrypted data with cipher in GCM mode                                  |

## Argon2DataEncryptionService

Data encryption service with Argon2id algorithm.

### Encryption process

- A block cipher service is initialized with the specified cipher in GCM mode.
- A random 16-bytes salt and a random 12-bytes nonce are generated.
- A 32-bytes key is generated with Argon2id algorithm.
- The header is written to the output stream.
- The input stream is encrypted into the output stream with the key and nonce.
- The key is cleared from memory.

### Decryption process

- The header is read from the input stream.
- A 32-bytes key is generated with Argon2 algorithm.
- A block cipher service is initialized with the cipher in GCM mode.
- The input stream is decrypted into the output stream with the key and nonce.

### Data structure

| Name            | Length (bytes) | Description                                                             |
|-----------------|----------------|-------------------------------------------------------------------------|
| Identifier      | 2              | Fixed value `[0xec, 0xde]` that identifies encryption with this library |
| Encryption type | 1              | Fixed value `0x02` that identifies encryption with Argon2               |
| Version         | 1              | Current version: `0x01`                                                 |
| Cipher          | 1              | Cipher identifier (see table below)                                     |
| Nonce           | 12             | Random nonce for encryption with GCM mode                               |
| Salt            | 16             | Random salt for Argon2                                                  |
| Iterations      | 4 (Int32)      | Number of iterations for Argon2                                         |
| Parallelism     | 4 (Int32)      | Parallelism factor for Argon2                                           |
| Memory pow2     | 4 (Int32)      | Memory cost factor (power of two) for Argon2                            |
| Encrypted data  | (dynamic)      | Encrypted data with cipher in GCM mode                                  |

## RsaDataEncryptionService

Data encryption service with RSA.

### Encryption process

- A block cipher service is initialized with the specified cipher in GCM mode.
- A random 32-bytes key and a random 12-bytes nonce are generated.
- The random key is encrypted with the public RSA key.
- The header is written to the output stream.
- The input stream is encrypted into the output stream with the key and nonce.
- The key is cleared from memory.

### Decryption process

- The header is read from the input stream.
- The encrypted key read from header is decrypted with the private RSA key.
- A block cipher service is initialized with the cipher in GCM mode.
- The input stream is decrypted into the output stream with the key and nonce.
- The decrypted key is cleared from memory.

### Data structure

| Name                 | Length (bytes) | Description                                                             |
|----------------------|----------------|-------------------------------------------------------------------------|
| Identifier           | 2              | Fixed value `[0xec, 0xde]` that identifies encryption with this library |
| Encryption type      | 1              | Fixed value `0x03` that identifies encryption with RSA                  |
| Version              | 1              | Current version: `0x01`                                                 |
| Cipher               | 1              | Cipher identifier (see table below)                                     |
| Nonce                | 12             | Random nonce for encryption with GCM mode                               |
| Encrypted key length | 4 (Int32)      | RSA-encrypted random key length                                         |
| Encrypted key        | (dynamic)      | RSA-encrypted random key                                                |
| Encrypted data       | (dynamic)      | Encrypted data with cipher in GCM mode                                  |

## MLKemDataEncryptionService

Data encryption service with ML-KEM.

### Encryption process

- A block cipher service is initialized with the specified cipher in GCM mode.
- A random 12-bytes nonce is generated.
- A 32-bytes key is generated from the ML-KEM public key.
- The header is written to the output stream.
- The input stream is encrypted into the output stream with the key and nonce.
- The key is cleared from memory.

### Decryption process

- The header is read from the input stream.
- The key is decapsulated with the ML-KEM private key.
- A block cipher service is initialized with the cipher in GCM mode.
- The input stream is decrypted into the output stream with the key and nonce.
- The decrypted key is cleared from memory.

### Data structure

| Name                 | Length (bytes) | Description                                                             |
|----------------------|----------------|-------------------------------------------------------------------------|
| Identifier           | 2              | Fixed value `[0xec, 0xde]` that identifies encryption with this library |
| Encryption type      | 1              | Fixed value `0x04` that identifies encryption with ML-KEM               |
| Version              | 1              | Current version: `0x01`                                                 |
| Cipher               | 1              | Cipher identifier (see table below)                                     |
| Nonce                | 12             | Random nonce for encryption with GCM mode                               |
| Encapsulation length | 4 (Int32)      | Encapsulation length                                                    |
| Encapsulation        | (dynamic)      | Encapsulation                                                           |
| Encrypted data       | (dynamic)      | Encrypted data with cipher in GCM mode                                  |
