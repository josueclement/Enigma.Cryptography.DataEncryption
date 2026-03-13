# Code Review — Enigma.Cryptography.DataEncryption

**Date:** 2026-03-13
**Scope:** All source files, tests, project files, and documentation
**Severity scale:** Critical > High > Medium > Low > Info

---

## 1. Security

### 1.1 Key material not cleared on exception paths — High

All four services call `Array.Clear(key, 0, key.Length)` at the end of `EncryptAsync`/`DecryptAsync`, but the call is **not** inside a `try/finally` block. If `bcs.EncryptAsync`, `bcs.DecryptAsync`, or any preceding line throws, the key bytes remain in memory.

**Affected locations:**

| Service | Encrypt | Decrypt |
|---|---|---|
| `Pbkdf2DataEncryptionService.cs` | line 109 | line 204 |
| `Argon2DataEncryptionService.cs` | line 124 | line 225 |
| `RsaDataEncryptionService.cs` | line 147 | line 244 |
| `MLKemDataEncryptionService.cs` | line 148 | line 245 |

**Recommendation:** Wrap the key-usage region in `try/finally` so that `Array.Clear` runs regardless of exceptions:

```csharp
var key = /* derive or generate */;
try
{
    // use key ...
}
finally
{
    Array.Clear(key, 0, key.Length);
}
```

### 1.2 No input validation on public methods — Medium

None of the four services validate their public method parameters. Null streams, null passwords, null keys, zero/negative iteration counts, and invalid `Cipher` enum values all propagate unchecked until they hit an internal NRE or cryptographic library error.

**Examples:**

- `Pbkdf2DataEncryptionService.EncryptAsync` (`Pbkdf2DataEncryptionService.cs:73`) — `input`, `output`, `password` could be `null`; `iterations` could be `<= 0`
- `Argon2DataEncryptionService.EncryptAsync` (`Argon2DataEncryptionService.cs:86`) — `password` byte array could be `null` or empty
- `RsaDataEncryptionService.EncryptAsync` (`RsaDataEncryptionService.cs:109`) — `publicKey` could be the wrong key type (see 1.3)
- `MLKemDataEncryptionService.EncryptAsync` (`MLKemDataEncryptionService.cs:111`) — same

**Recommendation:** Add `ArgumentNullException`/`ArgumentOutOfRangeException` guard clauses at the top of each public method.

### 1.3 Unsafe key-type casts in RSA and ML-KEM services — Medium

Both services accept `AsymmetricKeyParameter` (a base type) but internally hard-cast to specific derived types without guarding:

- `RsaDataEncryptionService.MatchesFingerprint` (`RsaDataEncryptionService.cs:45`): `(RsaPrivateCrtKeyParameters)privateKey` — throws `InvalidCastException` if passed a non-RSA key
- `MLKemDataEncryptionService.ComputeKeyFingerprint` (`MLKemDataEncryptionService.cs:29`): `((MLKemPublicKeyParameters)publicKey).GetEncoded()` — throws `InvalidCastException` if passed a non-ML-KEM key
- `MLKemDataEncryptionService.MatchesFingerprint` (`MLKemDataEncryptionService.cs:46`): `(MLKemPrivateKeyParameters)privateKey`

**Recommendation:** Either accept the concrete key types in the public API signatures, or guard the cast with an `is` check and throw `ArgumentException` with a clear message.

### 1.4 Fingerprint comparison is not constant-time — Low

`MatchesFingerprint` in both `RsaDataEncryptionService` (line 50) and `MLKemDataEncryptionService` (line 52) uses an early-return byte-by-byte comparison loop. This is theoretically vulnerable to timing side-channels.

**Recommendation:** Use a constant-time comparison (e.g., `CryptographicOperations.FixedTimeEquals` on .NET 6+, or a manual XOR-accumulator for netstandard2.0). The practical risk is low because the fingerprint is derived from a public key, but constant-time comparison is a good cryptographic hygiene practice.

### 1.5 Cipher byte not validated on decrypt — Low

In each service's `ReadHeaderAsync`, the cipher byte is cast directly to the `Cipher` enum without checking that the value is defined (`Cipher.cs:7–31`). An invalid byte will eventually fail at `CipherUtils.GetBlockCipherService` (`CipherUtils.cs:37`) with `"Invalid value for cipher"`, but a more specific error at parse time would improve debuggability.

---

## 2. Code Quality

### 2.1 Significant structural duplication across all four services — Medium

All four services follow the exact same encrypt/decrypt pattern:

1. Create factory instances (`BlockCipherServiceFactory`, `BlockCipherEngineFactory`, `BlockCipherParametersFactory`)
2. Call `CipherUtils.GetBlockCipherService`
3. Generate/derive key material
4. Write/read header
5. Encrypt/decrypt via `bcs`
6. Clear key

The four-line factory instantiation block is copy-pasted verbatim into **eight** methods:

- `Pbkdf2DataEncryptionService.cs:84–87` and `183–186`
- `Argon2DataEncryptionService.cs:99–102` and `204–207`
- `RsaDataEncryptionService.cs:120–122` and `219–222`
- `MLKemDataEncryptionService.cs:122–124` and `220–223`

**Recommendation:** Extract shared infrastructure into a base class or internal helper. The header identifier/version validation logic (identical across all `ReadHeaderAsync` methods) is another candidate for consolidation.

### 2.2 Factory instances created per method call — Low

Each `EncryptAsync`/`DecryptAsync` call creates new `BlockCipherServiceFactory`, `BlockCipherEngineFactory`, and `BlockCipherParametersFactory` instances. If these factories are stateless (likely), they could be static fields or injected once.

### 2.3 Dead test helper in RSA tests — Info

`RsaDataEncryptionServiceTests.Encrypt` (`RsaDataEncryptionServiceTests.cs:16–25`) generates an RSA key pair internally, encrypts, and returns only the ciphertext — making decryption impossible since the private key is lost. This helper is never called by any test; all round-trip tests inline the key generation logic.

### 2.4 `ComputeKeyFingerprint` duplication — Low

`RsaDataEncryptionService.ComputeKeyFingerprint` (`RsaDataEncryptionService.cs:26–35`) and `MLKemDataEncryptionService.ComputeKeyFingerprint` (`MLKemDataEncryptionService.cs:27–35`) share the same SHA-256-then-truncate-to-16-bytes pattern. Only the key serialization differs. A shared utility could reduce this.

### 2.5 `MatchesFingerprint` duplication — Low

`RsaDataEncryptionService.MatchesFingerprint` (`RsaDataEncryptionService.cs:43–54`) and `MLKemDataEncryptionService.MatchesFingerprint` (`MLKemDataEncryptionService.cs:44–55`) have an identical comparison loop. The only difference is how the public key is extracted from the private key.

---

## 3. Testing

### 3.1 RSA and ML-KEM tests missing Serpent and Camellia cipher coverage — Medium

PBKDF2 and Argon2 tests cover all four ciphers (AES, Twofish, Serpent, Camellia). The RSA and ML-KEM tests only cover AES and Twofish:

| Service tests | AES | Twofish | Serpent | Camellia |
|---|---|---|---|---|
| `Pbkdf2DataEncryptionServiceTests.cs` | line 36 | line 44 | line 52 | line 60 |
| `Argon2DataEncryptionServiceTests.cs` | line 36 | line 44 | line 52 | line 60 |
| `RsaDataEncryptionServiceTests.cs` | line 28 | line 46 | **missing** | **missing** |
| `MLKemDataEncryptionServiceTests.cs` | line 18 | line 36 | **missing** | **missing** |

**Recommendation:** Add `RoundTrip_Serpent256Gcm` and `RoundTrip_Camellia256Gcm` tests for both RSA and ML-KEM services.

### 3.2 No empty-data round-trip tests for RSA and ML-KEM — Low

PBKDF2 and Argon2 both have `EmptyData_RoundTrip` tests (`Pbkdf2DataEncryptionServiceTests.cs:80`, `Argon2DataEncryptionServiceTests.cs:79`). RSA and ML-KEM do not.

### 3.3 Test project targets net9.0 while library dropped it — Low

`UnitTests.csproj:3` targets `net9.0`, but the library (`Enigma.Cryptography.DataEncryption.csproj:5`) now targets `netstandard2.0;net10.0`. Tests are running against the netstandard2.0 build of the library rather than the net10.0 build. Consider targeting `net10.0` in the test project to also exercise the net10.0 TFM code paths.

### 3.4 No negative/boundary tests for password-based services — Low

There are no tests for:
- Null/empty password (PBKDF2: `string`, Argon2: `byte[]`)
- Zero or negative iteration count (PBKDF2)
- Invalid `Cipher` enum value
- Truncated/corrupted ciphertext (beyond wrong-password tests)
- Cancellation token behavior (cancellation during encrypt/decrypt)

---

## 4. Documentation & Configuration

### 4.1 CLAUDE.md references non-existent ConsoleApp1 project — Medium

`CLAUDE.md` contains:

```
# Build and run the console demo app (manual integration test)
dotnet run --project ConsoleApp1/ConsoleApp1.csproj
```

and describes the architecture as:

> **Demo/smoke-test app:** `ConsoleApp1/` — exercises all four services against in-memory streams

No `ConsoleApp1/` directory exists in the repository. This was removed in commit `accabc6` ("Replace manual test console application with xUnit test suite").

### 4.2 CLAUDE.md lists outdated target frameworks — Medium

`CLAUDE.md` states the library is a "multi-target .NET library (`netstandard2.0`, `netstandard2.1`, `net472`, `net6.0`–`net9.0`)". The actual target frameworks in `Enigma.Cryptography.DataEncryption.csproj:5` are `netstandard2.0;net10.0`.

### 4.3 Copyright year mismatch between LICENSE.md and csproj — Low

- `LICENSE.md:1`: `Copyright (c) 2025 Josue Clement`
- `Enigma.Cryptography.DataEncryption.csproj:9`: `Copyright © 2026 Josue Clement`

One of these needs to be updated for consistency.

### 4.4 No CI configuration — Info

There is no CI/CD configuration (GitHub Actions, Azure Pipelines, etc.) in the repository. For a published NuGet package, automated build/test/pack on push would help prevent regressions.

---

## Summary

| Severity | Count | Key items |
|---|---|---|
| Critical | 0 | |
| High | 1 | Key material not cleared on exception paths |
| Medium | 5 | No input validation, unsafe casts, code duplication, missing test coverage, stale CLAUDE.md |
| Low | 7 | Non-constant-time comparison, cipher validation, factory instantiation, copyright mismatch, etc. |
| Info | 2 | Dead test helper, no CI |
