using System;
using Enigma.BlockCiphers;

namespace Enigma.Cryptography.DataEncryption;

/// <summary>
/// Provides utility methods for working with cryptographic ciphers.
/// </summary>
/// <remarks>
/// This class contains factory methods that help create appropriate block cipher services
/// based on the requested cipher algorithm.
/// </remarks>
internal static class CipherUtils
{
    /// <summary>
    /// Creates and returns an appropriate block cipher service based on the specified cipher algorithm.
    /// </summary>
    /// <param name="cipher">The cipher algorithm to be used for encryption/decryption.</param>
    /// <param name="bcsFactory">The factory for creating block cipher services.</param>
    /// <param name="bcsEngineFactory">The factory for creating block cipher engines.</param>
    /// <returns>An implementation of <see cref="IBlockCipherService"/> configured with the specified cipher.</returns>
    /// <exception cref="InvalidOperationException">Thrown when an unsupported cipher algorithm is specified.</exception>
    /// <remarks>
    /// This method supports various cipher algorithms with Galois/Counter Mode (GCM),
    /// including AES-256, Twofish-256, Serpent-256, and Camellia-256.
    /// </remarks>
    public static IBlockCipherService GetBlockCipherService(
        Cipher cipher,
        BlockCipherServiceFactory bcsFactory,
        BlockCipherEngineFactory bcsEngineFactory)
        => cipher switch
        {
            Cipher.Aes256Gcm => bcsFactory.CreateGcmService(bcsEngineFactory.CreateAesEngine),
            Cipher.Twofish256Gcm => bcsFactory.CreateGcmService(bcsEngineFactory.CreateTwofishEngine),
            Cipher.Serpent256Gcm => bcsFactory.CreateGcmService(bcsEngineFactory.CreateSerpentEngine),
            Cipher.Camellia256Gcm => bcsFactory.CreateGcmService(bcsEngineFactory.CreateCamelliaEngine),
            _ => throw new InvalidOperationException("Invalid value for cipher")
        };
}