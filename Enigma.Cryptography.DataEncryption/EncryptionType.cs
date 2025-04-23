namespace Enigma.Cryptography.DataEncryption;

/// <summary>
/// Specifies the encryption algorithm type to be used for data protection.
/// </summary>
public enum EncryptionType : byte
{
    /// <summary>
    /// Password-Based Key Derivation Function 2 (PBKDF2).
    /// A key derivation function that applies a pseudorandom function to derive keys with repeated hashing.
    /// </summary>
    Pbkdf2 = 0x01,

    /// <summary>
    /// Argon2 key derivation function.
    /// A modern password-hashing function designed to be resistant against GPU, ASIC, and side-channel attacks.
    /// </summary>
    Argon2 = 0x02,

    /// <summary>
    /// RSA (Rivest–Shamir–Adleman) asymmetric encryption algorithm.
    /// Used for secure data transmission with a public/private key pair.
    /// </summary>
    Rsa = 0x03,

    /// <summary>
    /// ML-KEM (Machine Learning Key Encapsulation Mechanism).
    /// A post-quantum cryptographic algorithm designed to be secure against quantum computer attacks.
    /// </summary>
    // ReSharper disable once InconsistentNaming
    MLKem = 0x04
}