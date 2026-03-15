# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build the library
dotnet build Enigma.Cryptography.DataEncryption/Enigma.Cryptography.DataEncryption.csproj

# Run the unit tests (xUnit v3 — uses dotnet run, not dotnet test)
dotnet run --project UnitTests/UnitTests.csproj

# Pack the NuGet package
dotnet pack Enigma.Cryptography.DataEncryption/Enigma.Cryptography.DataEncryption.csproj
```

## Architecture

This is a multi-target .NET library (`netstandard2.0`, `net8.0`) that wraps the `Enigma.Cryptography` NuGet package to provide stream-based encryption/decryption services.

**Main library:** `Enigma.Cryptography.DataEncryption/`

### Encryption Services

Each service (`*DataEncryptionService.cs`) exposes `EncryptAsync` / `DecryptAsync` operating on `Stream` pairs with optional `IProgress<int>` and `CancellationToken`.

**Encrypt path** (`EncryptAsync` → `WriteHeaderAsync` → block cipher):

1. Write a binary header to the output stream (identifier `[0xec, 0xde]`, type byte, `CurrentVersion`, cipher byte, nonce, KDF/key-exchange parameters)
2. Encrypt the stream body using a block cipher in GCM mode via `Enigma.Cryptography.BlockCiphers`
3. Zero out the key bytes after use with `Array.Clear`

**Decrypt path** (`DecryptAsync` → `ReadCommonPrefixAsync` → `switch (version)` → `DecryptV*Async`):

1. `ReadCommonPrefixAsync` reads and validates the 4-byte common prefix (identifier, type, version) and returns the version byte
2. `DecryptAsync` dispatches on the version to a self-contained `DecryptV*Async` private method
3. `DecryptV*Async` reads the remaining version-specific header fields, derives/decapsulates the key, decrypts, and clears the key

This structure means adding a new version only requires a new `DecryptV*Async` method and a new `case` — existing version arms are never modified.

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

Every encrypted blob starts with a 4-byte common prefix (read by `ReadCommonPrefixAsync`):

| Field | Bytes | Value |
|---|---|---|
| Identifier | 2 | `0xec 0xde` |
| Encryption type | 1 | see `EncryptionType` |
| Version | 1 | `0x01` or `0x02` (depends on type) |

Followed by version-specific fields (cipher, nonce, salt, iterations, encapsulation, etc.) and then the GCM-encrypted payload. Full layouts are documented in `README.md`.
