using Enigma.Cryptography.BlockCiphers;
using System;
using System.IO;
using System.Security.Cryptography;

namespace Enigma.Cryptography.DataEncryption;

internal static class CryptoHelpers
{
    internal static readonly BlockCipherServiceFactory BcsFactory = new();
    internal static readonly BlockCipherEngineFactory BcsEngineFactory = new();
    internal static readonly BlockCipherParametersFactory BcsParametersFactory = new();

    internal static Cipher ValidateCipher(byte cipherValue)
    {
        if (!Enum.IsDefined(typeof(Cipher), cipherValue))
            throw new InvalidDataException($"Invalid cipher value: 0x{cipherValue:x2}");
        return (Cipher)cipherValue;
    }

    internal static bool FixedTimeEquals(byte[] left, byte[] right)
    {
        if (left.Length != right.Length)
            return false;

#if NETSTANDARD2_0
        var result = 0;
        for (var i = 0; i < left.Length; i++)
            result |= left[i] ^ right[i];
        return result == 0;
#else
        return CryptographicOperations.FixedTimeEquals(left, right);
#endif
    }

    internal static byte[] ComputeFingerprint(byte[] data)
    {
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(data);
        var fingerprint = new byte[16];
        Array.Copy(hash, fingerprint, 16);
        return fingerprint;
    }
}
