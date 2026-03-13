# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build the library
dotnet build Enigma.Cryptography.DataEncryption/Enigma.Cryptography.DataEncryption.csproj

# Run the unit tests
dotnet test UnitTests/UnitTests.csproj

# Pack the NuGet package
dotnet pack Enigma.Cryptography.DataEncryption/Enigma.Cryptography.DataEncryption.csproj
```

## Architecture

This is a multi-target .NET library (`netstandard2.0`, `net10.0`) that wraps the `Enigma.Cryptography` NuGet package to provide stream-based encryption/decryption services.

**Main library:** `Enigma.Cryptography.DataEncryption/`

### Encryption Services

Each service (`*DataEncryptionService.cs`) exposes `EncryptAsync` / `DecryptAsync` operating on `Stream` pairs with optional `IProgress<int>` and `CancellationToken`. They all follow the same internal pattern:

1. Write a binary header to the output stream (identifier `[0xec, 0xde]`, type byte, version `0x01`, cipher byte, nonce, KDF/key-exchange parameters)
2. Encrypt/decrypt the stream body using a block cipher in GCM mode via `Enigma.Cryptography.BlockCiphers`
3. Zero out the key bytes after use with `Array.Clear`

| Service | Key derivation / exchange | `EncryptionType` byte |
|---|---|---|
| `Pbkdf2DataEncryptionService` | PBKDF2 (password `string`) | `0x01` |
| `Argon2DataEncryptionService` | Argon2id (password `byte[]`) | `0x02` |
| `RsaDataEncryptionService` | RSA (BouncyCastle `AsymmetricKeyParameter`) | `0x03` |
| `MLKemDataEncryptionService` | ML-KEM-1024 post-quantum KEM | `0x04` |

### Shared Types

- `Cipher` enum — selects the block cipher: `Aes256Gcm`, `Twofish256Gcm`, `Serpent256Gcm`, `Camellia256Gcm`
- `EncryptionType` enum — identifies the KDF/key-exchange method in the binary header
- `CipherUtils.GetBlockCipherService` — internal factory helper that maps a `Cipher` value to an `IBlockCipherService`

### Binary Format

Every encrypted blob starts with a common prefix:

| Field | Bytes | Value |
|---|---|---|
| Identifier | 2 | `0xec 0xde` |
| Encryption type | 1 | see `EncryptionType` |
| Version | 1 | `0x01` or `0x02` (depends on type) |
| Cipher | 1 | see `Cipher` |

Followed by KDF/key-exchange-specific fields (nonce, salt, iterations, encapsulation, etc.) and then the GCM-encrypted payload. Full layouts are documented in `README.md`.
