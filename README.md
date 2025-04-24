# Enigma.Cryptography.DataEncryption

Enigma.Cryptography.DataEncryption is a .NET library based on `Enigma.Cryptography`.

It provides services for data encryption in a ...

## Pbkdf2DataEncryptionService

Data encryption service with PBKDF2 algorithm.

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
| Encrypted data  | remaining data | Encrypted data with cipher in GCM mode                                  |

## Argon2DataEncryptionService

Data encryption service with Argon2id algorithm.

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
| Encrypted data  | remaining data | Encrypted data with cipher in GCM mode                                  |

## RsaDataEncryptionService

Data encryption service with RSA.

### Data structure

| Name                 | Length (bytes) | Description                                                             |
|----------------------|----------------|-------------------------------------------------------------------------|
| Identifier           | 2              | Fixed value `[0xec, 0xde]` that identifies encryption with this library |
| Encryption type      | 1              | Fixed value `0x02` that identifies encryption with Argon2               |
| Version              | 1              | Current version: `0x01`                                                 |
| Cipher               | 1              | Cipher identifier (see table below)                                     |
| Nonce                | 12             | Random nonce for encryption with GCM mode                               |
| Encrypted key length | 4 (Int32)      | RSA-encrypted random key length                                         |
| Encrypted key        | (dynamic)      | RSA-encrypted random key                                                |

## MLKemDataEncryptionService

Data encryption service with ML-KEM.

### Data structure

| Name                 | Length (bytes) | Description                                                             |
|----------------------|----------------|-------------------------------------------------------------------------|
| Identifier           | 2              | Fixed value `[0xec, 0xde]` that identifies encryption with this library |
| Encryption type      | 1              | Fixed value `0x02` that identifies encryption with Argon2               |
| Version              | 1              | Current version: `0x01`                                                 |
| Cipher               | 1              | Cipher identifier (see table below)                                     |
| Nonce                | 12             | Random nonce for encryption with GCM mode                               |
| Encapsulation length | 4 (Int32)      | Encapsulation length                                                    |
| Encapsulation        | (dynamic)      | Encapsulation                                                           |
