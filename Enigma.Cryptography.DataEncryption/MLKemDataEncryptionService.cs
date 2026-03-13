using Enigma.Cryptography.BlockCiphers;
using Enigma.Cryptography.Extensions;
using Enigma.Cryptography.PQC;
using Enigma.Cryptography.Utils;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Threading;
using System;

namespace Enigma.Cryptography.DataEncryption;

/// <summary>
/// Provides data encryption services using ML-KEM (Module Lattice Key Encapsulation Mechanism) for key exchange
/// combined with symmetric block ciphers for data encryption.
/// ML-KEM is a post-quantum cryptography algorithm designed to be secure against quantum computer attacks.
/// </summary>
// ReSharper disable once InconsistentNaming
public class MLKemDataEncryptionService
{
    /// <summary>
    /// Computes a 16-byte key fingerprint as the first 16 bytes of the SHA-256 hash
    /// of the public key's encoded bytes.
    /// </summary>
    private static byte[] ComputeKeyFingerprint(AsymmetricKeyParameter publicKey)
    {
        if (publicKey is not MLKemPublicKeyParameters mlKemPub)
            throw new ArgumentException("Expected an ML-KEM public key.", nameof(publicKey));
        var keyBytes = mlKemPub.GetEncoded();
        return CryptoHelpers.ComputeFingerprint(keyBytes);
    }

    /// <summary>
    /// Determines whether the given ML-KEM private key corresponds to the specified key fingerprint.
    /// </summary>
    /// <param name="privateKey">The ML-KEM private key to check.</param>
    /// <param name="fingerprint">The 16-byte fingerprint to match against.</param>
    /// <returns><c>true</c> if the private key's derived public key produces the same fingerprint; otherwise <c>false</c>.</returns>
    // ReSharper disable once InconsistentNaming
    public static bool MatchesFingerprint(AsymmetricKeyParameter privateKey, byte[] fingerprint)
    {
        if (privateKey is not MLKemPrivateKeyParameters mlKemPriv)
            throw new ArgumentException("Expected an ML-KEM private key.", nameof(privateKey));
        var publicKey = mlKemPriv.GetPublicKey();
        var computed = ComputeKeyFingerprint(publicKey);
        return CryptoHelpers.FixedTimeEquals(computed, fingerprint);
    }

    /// <summary>
    /// Writes the encryption header to the output stream. The header contains encryption
    /// parameters that will be used later during decryption.
    /// </summary>
    /// <param name="output">The stream to write the header to</param>
    /// <param name="cipherValue">The byte representing the cipher algorithm used</param>
    /// <param name="keyFingerprint">The 16-byte fingerprint of the ML-KEM public key used to encrypt</param>
    /// <param name="nonce">The nonce/initialization vector used for encryption</param>
    /// <param name="encapsulation">The ML-KEM encapsulation data</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>A task representing the asynchronous operation</returns>
    private async Task WriteHeaderAsync(
        Stream output,
        byte cipherValue,
        byte[] keyFingerprint,
        byte[] nonce,
        byte[] encapsulation,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Identifier
        await output.WriteBytesAsync([0xec, 0xde]).ConfigureAwait(false);

        // Type
        await output.WriteByteAsync((byte)EncryptionType.MLKem).ConfigureAwait(false);

        // Version
        await output.WriteByteAsync(0x02).ConfigureAwait(false);

        // Cipher
        await output.WriteByteAsync(cipherValue).ConfigureAwait(false);

        // Key fingerprint
        await output.WriteBytesAsync(keyFingerprint).ConfigureAwait(false);

        // Nonce
        await output.WriteBytesAsync(nonce).ConfigureAwait(false);

        // Encapsulation
        await output.WriteLengthValueAsync(encapsulation).ConfigureAwait(false);
    }

    /// <summary>
    /// Encrypts data from the input stream to the output stream using ML-KEM key encapsulation
    /// combined with a symmetric block cipher.
    /// </summary>
    /// <param name="input">The stream containing plaintext data to encrypt</param>
    /// <param name="output">The stream where encrypted data will be written</param>
    /// <param name="cipher">The symmetric cipher algorithm to use</param>
    /// <param name="publicKey">The recipient's ML-KEM public key</param>
    /// <param name="progress">Optional progress reporting</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>A task representing the asynchronous encryption operation</returns>
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

        var mlKemService = new MLKemServiceFactory().CreateKem1024();

        // Get block cipher service from cipher enum
        var bcs = CipherUtils.GetBlockCipherService(cipher, CryptoHelpers.BcsFactory, CryptoHelpers.BcsEngineFactory);

        // Generate random nonce
        var nonce = RandomUtils.GenerateRandomBytes(12);

        // Compute key fingerprint
        var keyFingerprint = ComputeKeyFingerprint(publicKey);

        // Encapsulate secret key using public key
        var (encapsulation, secret) = mlKemService.Encapsulate(publicKey);

        try
        {
            // Create GCM parameters for block cipher service
            var bcsParameters = CryptoHelpers.BcsParametersFactory.CreateGcmParameters(secret, nonce);

            // Write header
            await WriteHeaderAsync(output, (byte)cipher, keyFingerprint, nonce, encapsulation, cancellationToken).ConfigureAwait(false);

            // Encrypt data
            await bcs.EncryptAsync(input, output, bcsParameters, progress, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Clear key from memory
            Array.Clear(secret, 0, secret.Length);
        }
    }

    /// <summary>
    /// Reads and parses the encryption header from the input stream to extract
    /// the parameters needed for decryption.
    /// </summary>
    /// <param name="input">The stream to read the header from</param>
    /// <param name="progress">Optional progress reporting</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>A tuple containing the cipher type, key fingerprint, nonce, and encapsulation data</returns>
    /// <exception cref="InvalidDataException">Thrown when header validation fails</exception>
    private async Task<(Cipher cipher, byte[] keyFingerprint, byte[] nonce, byte[] encapsulation)> ReadHeaderAsync(
        Stream input,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Identifier
        var header = await input.ReadBytesAsync(2).ConfigureAwait(false);
        if (header[0] != 0xec || header[1] != 0xde)
            throw new InvalidDataException("Invalid header");

        // Type
        var typeValue = await input.ReadByteAsync().ConfigureAwait(false);
        if ((EncryptionType)typeValue != EncryptionType.MLKem)
            throw new InvalidDataException("Invalid encryption type");

        // Version
        var version = await input.ReadByteAsync().ConfigureAwait(false);
        if (version != 0x02)
            throw new InvalidDataException("Invalid version");

        // Cipher
        var cipherValue = await input.ReadByteAsync().ConfigureAwait(false);
        var cipher = CryptoHelpers.ValidateCipher(cipherValue);

        // Key fingerprint
        var keyFingerprint = await input.ReadBytesAsync(16).ConfigureAwait(false);

        // Nonce
        var nonce = await input.ReadBytesAsync(12).ConfigureAwait(false);

        // Encapsulation
        var encapsulation = await input.ReadLengthValueAsync().ConfigureAwait(false);

        // Progress
        progress?.Report(37 + encapsulation.Length);

        return (cipher, keyFingerprint, nonce, encapsulation);
    }

    /// <summary>
    /// Decrypts data from the input stream to the output stream using ML-KEM and a symmetric block cipher.
    /// </summary>
    /// <param name="input">The stream containing encrypted data to decrypt</param>
    /// <param name="output">The stream where decrypted data will be written</param>
    /// <param name="privateKey">The recipient's ML-KEM private key</param>
    /// <param name="progress">Optional progress reporting</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
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

        var mlKemService = new MLKemServiceFactory().CreateKem1024();

        // Read header
        var (cipher, keyFingerprint, nonce, encapsulation) = await ReadHeaderAsync(input, progress, cancellationToken).ConfigureAwait(false);

        // Validate private key matches fingerprint
        if (!MatchesFingerprint(privateKey, keyFingerprint))
            throw new InvalidOperationException("The private key does not match the key fingerprint stored in the header.");

        // Get block cipher service from cipher enum
        var bcs = CipherUtils.GetBlockCipherService(cipher, CryptoHelpers.BcsFactory, CryptoHelpers.BcsEngineFactory);

        // Decapsulate secret key using private key
        var secret = mlKemService.Decapsulate(encapsulation, privateKey);

        try
        {
            // Create GCM parameters for block cipher service
            var bcsParameters = CryptoHelpers.BcsParametersFactory.CreateGcmParameters(secret, nonce);

            // Decrypt data
            await bcs.DecryptAsync(input, output, bcsParameters, progress, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Clear key from memory
            Array.Clear(secret, 0, secret.Length);
        }
    }
}
