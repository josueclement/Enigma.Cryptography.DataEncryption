using Enigma.Cryptography.BlockCiphers;
using Enigma.Cryptography.Extensions;
using Enigma.Cryptography.PublicKey;
using Enigma.Cryptography.Utils;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Threading;
using System;

namespace Enigma.Cryptography.DataEncryption;

/// <summary>
/// Provides functionality for encrypting and decrypting data using RSA public/private key pairs
/// in combination with symmetric block ciphers operating in GCM mode.
/// </summary>
public class RsaDataEncryptionService
{
    private const byte CurrentVersion = 0x02;

    /// <summary>
    /// Computes a 16-byte key fingerprint as the first 16 bytes of the SHA-256 hash
    /// of the public key's SubjectPublicKeyInfo DER encoding.
    /// </summary>
    private static byte[] ComputeKeyFingerprint(AsymmetricKeyParameter publicKey)
    {
        var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
        var der = spki.GetDerEncoded();
        return CryptoHelpers.ComputeFingerprint(der);
    }

    /// <summary>
    /// Determines whether the given RSA private key corresponds to the specified key fingerprint.
    /// </summary>
    /// <param name="privateKey">The RSA private key to check.</param>
    /// <param name="fingerprint">The 16-byte fingerprint to match against.</param>
    /// <returns><c>true</c> if the private key's derived public key produces the same fingerprint; otherwise <c>false</c>.</returns>
    public static bool MatchesFingerprint(AsymmetricKeyParameter privateKey, byte[] fingerprint)
    {
        if (privateKey is not RsaPrivateCrtKeyParameters rsaPriv)
            throw new ArgumentException("Expected an RSA private key.", nameof(privateKey));
        var publicKey = new RsaKeyParameters(false, rsaPriv.Modulus, rsaPriv.PublicExponent);
        var computed = ComputeKeyFingerprint(publicKey);
        return CryptoHelpers.FixedTimeEquals(computed, fingerprint);
    }

    /// <summary>
    /// Writes the encryption header to the output stream. The header contains encryption
    /// parameters that will be used later during decryption.
    /// </summary>
    /// <param name="output">The stream to write the header information to.</param>
    /// <param name="cipherValue">The byte value representing the cipher algorithm used.</param>
    /// <param name="keyFingerprint">The 16-byte fingerprint of the RSA public key used to encrypt.</param>
    /// <param name="nonce">The initialization vector (nonce) for the symmetric encryption.</param>
    /// <param name="encKey">The encrypted symmetric key.</param>
    /// <param name="cancellationToken">Optional token to monitor for cancellation requests.</param>
    /// <returns>A task representing the asynchronous write operation.</returns>
    private async Task WriteHeaderAsync(
        Stream output,
        byte cipherValue,
        byte[] keyFingerprint,
        byte[] nonce,
        byte[] encKey,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Identifier
        await output.WriteBytesAsync([0xec, 0xde]).ConfigureAwait(false);

        // Type
        await output.WriteByteAsync((byte)EncryptionType.Rsa).ConfigureAwait(false);

        // Version
        await output.WriteByteAsync(CurrentVersion).ConfigureAwait(false);

        // Cipher
        await output.WriteByteAsync(cipherValue).ConfigureAwait(false);

        // Key fingerprint
        await output.WriteBytesAsync(keyFingerprint).ConfigureAwait(false);

        // Nonce
        await output.WriteBytesAsync(nonce).ConfigureAwait(false);

        // Encrypted key
        await output.WriteLengthValueAsync(encKey).ConfigureAwait(false);
    }

    /// <summary>
    /// Encrypts data from the input stream and writes the encrypted data to the output stream using RSA encryption.
    /// </summary>
    /// <param name="input">The stream containing the data to encrypt.</param>
    /// <param name="output">The stream where the encrypted data will be written.</param>
    /// <param name="cipher">The symmetric cipher algorithm to use for the data encryption (all operating in GCM mode).</param>
    /// <param name="publicKey">The RSA public key used to encrypt the symmetric key.</param>
    /// <param name="progress">Optional progress reporting mechanism.</param>
    /// <param name="cancellationToken">Optional token to monitor for cancellation requests.</param>
    /// <returns>A task representing the asynchronous encryption operation.</returns>
    public async Task EncryptAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        AsymmetricKeyParameter publicKey,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (input is null) throw new ArgumentNullException(nameof(input));
        if (output is null) throw new ArgumentNullException(nameof(output));
        if (publicKey is null) throw new ArgumentNullException(nameof(publicKey));
        if (!Enum.IsDefined(typeof(Cipher), cipher)) throw new ArgumentOutOfRangeException(nameof(cipher));

        var rsaService = new PublicKeyServiceFactory().CreateRsaService();

        // Get block cipher service from cipher enum
        var bcs = CipherUtils.GetBlockCipherService(cipher, CryptoHelpers.BcsFactory, CryptoHelpers.BcsEngineFactory);

        // Generate random key and nonce
        var key = RandomUtils.GenerateRandomBytes(32);
        var nonce = RandomUtils.GenerateRandomBytes(12);

        try
        {
            // Create GCM parameters for block cipher service
            var bcsParameters = CryptoHelpers.BcsParametersFactory.CreateGcmParameters(key, nonce);

            // Compute key fingerprint
            var keyFingerprint = ComputeKeyFingerprint(publicKey);

            // Encrypt key with public key
            var encKey = rsaService.Encrypt(key, publicKey);

            // Write header
            await WriteHeaderAsync(output, (byte)cipher, keyFingerprint, nonce, encKey, cancellationToken).ConfigureAwait(false);

            // Encrypt data
            await bcs.EncryptAsync(input, output, bcsParameters, progress, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Clear key from memory
            Array.Clear(key, 0, key.Length);
        }
    }

    /// <summary>
    /// Reads and validates the common prefix (identifier, type, version) from the input stream.
    /// </summary>
    /// <param name="input">The stream containing the encrypted data.</param>
    /// <param name="cancellationToken">Optional token to monitor for cancellation requests.</param>
    /// <returns>The version byte from the header.</returns>
    /// <exception cref="InvalidDataException">Thrown when the header identifier or type is invalid.</exception>
    private async Task<byte> ReadCommonPrefixAsync(
        Stream input,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Identifier
        var header = await input.ReadBytesAsync(2).ConfigureAwait(false);
        if (header[0] != 0xec || header[1] != 0xde)
            throw new InvalidDataException("Invalid header");

        // Type
        var typeValue = await input.ReadByteAsync().ConfigureAwait(false);
        if ((EncryptionType)typeValue != EncryptionType.Rsa)
            throw new InvalidDataException("Invalid encryption type");

        // Version
        return await input.ReadByteAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Decrypts data from the input stream and writes the decrypted data to the output stream using RSA decryption.
    /// </summary>
    /// <param name="input">The stream containing the encrypted data.</param>
    /// <param name="output">The stream where the decrypted data will be written.</param>
    /// <param name="privateKey">The RSA private key used to decrypt the symmetric key.</param>
    /// <param name="progress">Optional progress reporting mechanism.</param>
    /// <param name="cancellationToken">Optional token to monitor for cancellation requests.</param>
    /// <returns>A task representing the asynchronous decryption operation.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the private key does not match the key fingerprint stored in the header.</exception>
    public async Task DecryptAsync(
        Stream input,
        Stream output,
        AsymmetricKeyParameter privateKey,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (input is null) throw new ArgumentNullException(nameof(input));
        if (output is null) throw new ArgumentNullException(nameof(output));
        if (privateKey is null) throw new ArgumentNullException(nameof(privateKey));

        var version = await ReadCommonPrefixAsync(input, cancellationToken).ConfigureAwait(false);

        switch (version)
        {
            case 0x02:
                await DecryptV2Async(input, output, privateKey, progress, cancellationToken).ConfigureAwait(false);
                break;
            default:
                throw new InvalidDataException($"Unsupported version: 0x{version:x2}");
        }
    }

    private async Task DecryptV2Async(
        Stream input,
        Stream output,
        AsymmetricKeyParameter privateKey,
        IProgress<int>? progress,
        CancellationToken cancellationToken)
    {
        // Cipher
        var cipherValue = await input.ReadByteAsync().ConfigureAwait(false);
        var cipher = CryptoHelpers.ValidateCipher(cipherValue);

        // Key fingerprint
        var keyFingerprint = await input.ReadBytesAsync(16).ConfigureAwait(false);

        // Nonce
        var nonce = await input.ReadBytesAsync(12).ConfigureAwait(false);

        // Encrypted key
        var encKey = await input.ReadLengthValueAsync().ConfigureAwait(false);

        // Progress
        progress?.Report(37 + encKey.Length);

        // Validate private key matches fingerprint
        if (!MatchesFingerprint(privateKey, keyFingerprint))
            throw new InvalidOperationException("The private key does not match the key fingerprint stored in the header.");

        // Get block cipher service from cipher enum
        var bcs = CipherUtils.GetBlockCipherService(cipher, CryptoHelpers.BcsFactory, CryptoHelpers.BcsEngineFactory);

        // Decrypt key with private key
        var rsaService = new PublicKeyServiceFactory().CreateRsaService();
        var key = rsaService.Decrypt(encKey, privateKey);

        try
        {
            // Create GCM parameters for block cipher service
            var bcsParameters = CryptoHelpers.BcsParametersFactory.CreateGcmParameters(key, nonce);

            // Decrypt data
            await bcs.DecryptAsync(input, output, bcsParameters, progress, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Clear key from memory
            Array.Clear(key, 0, key.Length);
        }
    }
}
