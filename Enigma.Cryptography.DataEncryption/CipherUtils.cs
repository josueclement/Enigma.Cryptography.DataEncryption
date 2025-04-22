using System;
using Enigma.BlockCiphers;

namespace Enigma.Cryptography.DataEncryption;

public static class CipherUtils
{
    public static IBlockCipherService GetBlockCipherService(
        Ciphers cipher,
        BlockCipherServiceFactory bcsFactory,
        BlockCipherEngineFactory bcsEngineFactory)
        => cipher switch
        {
            Ciphers.AES_256_GCM => bcsFactory.CreateGcmService(bcsEngineFactory.CreateAesEngine),
            Ciphers.TWOFISH_256_GCM => bcsFactory.CreateGcmService(bcsEngineFactory.CreateTwofishEngine),
            Ciphers.SERPENT_256_GCM => bcsFactory.CreateGcmService(bcsEngineFactory.CreateSerpentEngine),
            Ciphers.CAMELLIA_256_GCM => bcsFactory.CreateGcmService(bcsEngineFactory.CreateCamelliaEngine),
            _ => throw new InvalidOperationException("Invalid value for cipher")
        };
}