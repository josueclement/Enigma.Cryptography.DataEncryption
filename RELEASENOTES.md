# Release Notes

## v1.2.0

### Security Improvements

- Key material is now guaranteed to be cleared via try/finally blocks in all encryption services
- Constant-time comparison used for fingerprint matching in RSA and ML-KEM services (prevents timing attacks)
- Cipher byte validated against `Enum.IsDefined` during header parsing to reject unknown values
- Safe cast patterns (`is not`) used for key type validation in RSA and ML-KEM services

### Code Quality

- New shared `CryptoHelpers` class consolidates duplicated factory instances, cipher validation, fingerprint computation, and constant-time comparison
- Input validation (guard clauses) added to all public `EncryptAsync`/`DecryptAsync` methods
- Removed unused `Encrypt` helper from `RsaDataEncryptionServiceTests`

### Testing

- Added Serpent-256-GCM and Camellia-256-GCM round-trip tests for RSA and ML-KEM services
- Added empty-data round-trip tests for RSA and ML-KEM services
- Added negative/boundary tests: null arguments, invalid cipher, truncated ciphertext, pre-cancelled tokens
- Test project updated to target net10.0

### Documentation

- Updated CLAUDE.md: removed ConsoleApp1 references, added test command, corrected target frameworks and version field
- Updated LICENSE.md copyright year to 2026
