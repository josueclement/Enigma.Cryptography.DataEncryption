# Enigma.Cryptography.DataEncryption

A .NET library built on top of [`Enigma.Cryptography`](https://www.nuget.org/packages/Enigma.Cryptography) that provides stream-based encryption and decryption services.

All services share the same `Stream`-in / `Stream`-out API with optional `IProgress<int>` and `CancellationToken` support. Every encrypted blob starts with a binary header that embeds all parameters needed for decryption (cipher, KDF settings, nonce, etc.), so no out-of-band metadata is required.

## Target frameworks

`netstandard2.0`, `net8.0`

## Available services

| Service | Key derivation / exchange |
|---|---|
| `Pbkdf2DataEncryptionService` | PBKDF2 (password as `string`) |
| `Argon2DataEncryptionService` | Argon2id (password as `byte[]`) |
| `RsaDataEncryptionService` | RSA public/private key pair |
| `MLKemDataEncryptionService` | ML-KEM-1024 (post-quantum KEM) |

## Ciphers

All services support the following symmetric ciphers operating in GCM mode:

| `Cipher` enum value | Identifier byte |
|---|---|
| `Aes256Gcm` | `0x01` |
| `Twofish256Gcm` | `0x02` |
| `Serpent256Gcm` | `0x03` |
| `Camellia256Gcm` | `0x04` |

---

## Pbkdf2DataEncryptionService

Password-based encryption using PBKDF2-HMAC-SHA256.

### Encryption process

1. Generate a random 16-byte salt and a random 12-byte nonce.
2. Derive a 32-byte key with PBKDF2 from the password, salt, and iteration count.
3. Write the header to the output stream.
4. Encrypt the input stream into the output stream using the selected cipher in GCM mode.
5. Clear the key from memory.

### Decryption process

1. Read and validate the common prefix (identifier, type, version) from the input stream.
2. Dispatch to the version-specific decryption handler based on the version byte.
3. Read the version-specific header fields (cipher, nonce, salt, iteration count).
4. Derive the 32-byte key with PBKDF2 using the password, salt, and iteration count from the header.
5. Decrypt the input stream into the output stream.
6. Clear the key from memory.

### Usage

```csharp
var service = new Pbkdf2DataEncryptionService();

// Encrypt
await service.EncryptAsync(inputStream, outputStream, Cipher.Aes256Gcm, "password", iterations: 100_000);

// Decrypt
await service.DecryptAsync(inputStream, outputStream, "password");
```

### Binary format

| Field | Size (bytes) | Description |
|---|---|---|
| Identifier | 2 | `0xec 0xde` — library magic bytes |
| Encryption type | 1 | `0x01` — PBKDF2 |
| Version | 1 | `0x01` |
| Cipher | 1 | Cipher identifier |
| Nonce | 12 | Random nonce for GCM |
| Salt | 16 | Random salt for PBKDF2 |
| Iterations | 4 (Int32) | PBKDF2 iteration count |
| Encrypted data | variable | GCM-encrypted payload |

---

## Argon2DataEncryptionService

Password-based encryption using Argon2id.

### Encryption process

1. Generate a random 16-byte salt and a random 12-byte nonce.
2. Derive a 32-byte key with Argon2id from the password, salt, and cost parameters.
3. Write the header to the output stream.
4. Encrypt the input stream into the output stream using the selected cipher in GCM mode.
5. Clear the key from memory.

### Decryption process

1. Read and validate the common prefix (identifier, type, version) from the input stream.
2. Dispatch to the version-specific decryption handler based on the version byte.
3. Read the version-specific header fields (cipher, nonce, salt, cost parameters).
4. Derive the 32-byte key with Argon2id using the password and cost parameters from the header.
5. Decrypt the input stream into the output stream.
6. Clear the key from memory.

### Usage

```csharp
var service = new Argon2DataEncryptionService();

// Encrypt
await service.EncryptAsync(inputStream, outputStream, Cipher.Aes256Gcm, passwordBytes);

// Decrypt
await service.DecryptAsync(inputStream, outputStream, passwordBytes);
```

### Binary format

| Field | Size (bytes) | Description |
|---|---|---|
| Identifier | 2 | `0xec 0xde` — library magic bytes |
| Encryption type | 1 | `0x02` — Argon2id |
| Version | 1 | `0x01` |
| Cipher | 1 | Cipher identifier |
| Nonce | 12 | Random nonce for GCM |
| Salt | 16 | Random salt for Argon2id |
| Iterations | 4 (Int32) | Argon2id iteration count |
| Parallelism | 4 (Int32) | Argon2id parallelism factor |
| Memory pow2 | 4 (Int32) | Argon2id memory cost (power of two) |
| Encrypted data | variable | GCM-encrypted payload |

---

## RsaDataEncryptionService

Hybrid encryption using an RSA public/private key pair to protect a random symmetric key.

### Encryption process

1. Generate a random 32-byte symmetric key and a random 12-byte nonce.
2. Compute a 16-byte key fingerprint: first 16 bytes of SHA-256 over the public key's SubjectPublicKeyInfo DER encoding.
3. Encrypt the symmetric key with the RSA public key.
4. Write the header to the output stream.
5. Encrypt the input stream into the output stream using the selected cipher in GCM mode.
6. Clear the symmetric key from memory.

### Decryption process

1. Read and validate the common prefix (identifier, type, version) from the input stream.
2. Dispatch to the version-specific decryption handler based on the version byte.
3. Read the version-specific header fields (cipher, key fingerprint, nonce, encrypted key).
4. Validate that the supplied private key matches the fingerprint stored in the header. Throws `InvalidOperationException` if they do not match.
5. Decrypt the encrypted symmetric key with the RSA private key.
6. Decrypt the input stream into the output stream.
7. Clear the symmetric key from memory.

### Usage

```csharp
var rsa = new PublicKeyServiceFactory().CreateRsaService();
var keyPair = rsa.GenerateKeyPair(4096);

var service = new RsaDataEncryptionService();

// Encrypt
await service.EncryptAsync(inputStream, outputStream, Cipher.Aes256Gcm, keyPair.Public);

// Decrypt — throws InvalidOperationException if the wrong private key is supplied
await service.DecryptAsync(inputStream, outputStream, keyPair.Private);
```

### Binary format

| Field | Size (bytes) | Description |
|---|---|---|
| Identifier | 2 | `0xec 0xde` — library magic bytes |
| Encryption type | 1 | `0x03` — RSA |
| Version | 1 | `0x02` |
| Cipher | 1 | Cipher identifier |
| Key fingerprint | 16 | First 16 bytes of SHA-256 of the RSA public key's SPKI DER encoding |
| Nonce | 12 | Random nonce for GCM |
| Encrypted key length | 4 (Int32) | Length of the RSA-encrypted symmetric key |
| Encrypted key | variable | RSA-encrypted symmetric key |
| Encrypted data | variable | GCM-encrypted payload |

---

## MLKemDataEncryptionService

Post-quantum hybrid encryption using ML-KEM-1024 (NIST FIPS 203) for key encapsulation, combined with a symmetric block cipher for data encryption.

### Encryption process

1. Generate a random 12-byte nonce.
2. Compute a 16-byte key fingerprint: first 16 bytes of SHA-256 over the public key's encoded bytes.
3. Encapsulate a shared secret from the ML-KEM-1024 public key, producing an encapsulation and a 32-byte secret.
4. Write the header to the output stream.
5. Encrypt the input stream into the output stream using the selected cipher in GCM mode with the shared secret as the key.
6. Clear the secret from memory.

### Decryption process

1. Read and validate the common prefix (identifier, type, version) from the input stream.
2. Dispatch to the version-specific decryption handler based on the version byte.
3. Read the version-specific header fields (cipher, key fingerprint, nonce, encapsulation).
4. Validate that the supplied private key matches the fingerprint stored in the header. Throws `InvalidOperationException` if they do not match.
5. Decapsulate the shared secret from the encapsulation using the ML-KEM-1024 private key.
6. Decrypt the input stream into the output stream.
7. Clear the secret from memory.

### Usage

```csharp
var mlKem = new MLKemServiceFactory().CreateKem1024();
var keyPair = mlKem.GenerateKeyPair();

var service = new MLKemDataEncryptionService();

// Encrypt
await service.EncryptAsync(inputStream, outputStream, Cipher.Aes256Gcm, keyPair.Public);

// Decrypt — throws InvalidOperationException if the wrong private key is supplied
await service.DecryptAsync(inputStream, outputStream, keyPair.Private);
```

### Binary format

| Field | Size (bytes) | Description |
|---|---|---|
| Identifier | 2 | `0xec 0xde` — library magic bytes |
| Encryption type | 1 | `0x04` — ML-KEM |
| Version | 1 | `0x02` |
| Cipher | 1 | Cipher identifier |
| Key fingerprint | 16 | First 16 bytes of SHA-256 of the ML-KEM public key's encoded bytes |
| Nonce | 12 | Random nonce for GCM |
| Encapsulation length | 4 (Int32) | Length of the ML-KEM encapsulation |
| Encapsulation | variable | ML-KEM encapsulation |
| Encrypted data | variable | GCM-encrypted payload |
