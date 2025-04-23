namespace Enigma.Cryptography.DataEncryption;

/// <summary>
/// Defines the supported encryption cipher algorithms used for data encryption.
/// Each cipher uses Galois/Counter Mode (GCM) with a 256-bit key length.
/// </summary>
public enum Cipher : byte
{
    /// <summary>
    /// Advanced Encryption Standard (AES) with 256-bit key length using Galois/Counter Mode.
    /// AES is a widely adopted symmetric encryption algorithm established by the U.S. NIST.
    /// </summary>
    Aes256Gcm = 0x01,
    
    /// <summary>
    /// Twofish encryption algorithm with 256-bit key length using Galois/Counter Mode.
    /// Twofish is a symmetric key block cipher with a block size of 128 bits, designed as an AES finalist.
    /// </summary>
    Twofish256Gcm = 0x02,
    
    /// <summary>
    /// Serpent encryption algorithm with 256-bit key length using Galois/Counter Mode.
    /// Serpent is a symmetric key block cipher that was a finalist in the AES competition.
    /// </summary>
    Serpent256Gcm = 0x03,
    
    /// <summary>
    /// Camellia encryption algorithm with 256-bit key length using Galois/Counter Mode.
    /// Camellia is a symmetric key block cipher jointly developed by Mitsubishi Electric and NTT.
    /// </summary>
    Camellia256Gcm = 0x04
}