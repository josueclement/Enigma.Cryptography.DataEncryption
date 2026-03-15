using Enigma.Cryptography.BlockCiphers;
using Enigma.Cryptography.Extensions;
using Enigma.Cryptography.KDF;
using Enigma.Cryptography.Utils;
using System.IO;
using System.Threading.Tasks;
using System.Threading;
using System;

namespace Enigma.Cryptography.DataEncryption;

/// <summary>
/// Provides encryption and decryption services using PBKDF2 for key derivation.
/// This service handles the encryption and decryption of data streams using password-based key derivation.
/// </summary>
public class Pbkdf2DataEncryptionService
{
    private const byte CurrentVersion = 0x01;

    /// <summary>
    /// Writes the encryption header to the output stream. The header contains encryption
    /// parameters that will be used later during decryption.
    /// </summary>
    /// <param name="output">The output stream to write the header to.</param>
    /// <param name="cipherValue">The byte value representing the cipher algorithm used.</param>
    /// <param name="nonce">The nonce bytes used for encryption.</param>
    /// <param name="salt">The salt bytes used for key derivation.</param>
    /// <param name="iterations">The number of iterations used in the PBKDF2 algorithm.</param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous write operation.</returns>
    private async Task WriteHeaderAsync(
        Stream output,
        byte cipherValue,
        byte[] nonce,
        byte[] salt,
        int iterations,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Identifier
        await output.WriteBytesAsync([0xec, 0xde]).ConfigureAwait(false);

        // Type
        await output.WriteByteAsync((byte)EncryptionType.Pbkdf2).ConfigureAwait(false);

        // Version
        await output.WriteByteAsync(CurrentVersion).ConfigureAwait(false);

        // Cipher
        await output.WriteByteAsync(cipherValue).ConfigureAwait(false);

        // Nonce
        await output.WriteBytesAsync(nonce).ConfigureAwait(false);

        // Salt
        await output.WriteBytesAsync(salt).ConfigureAwait(false);

        // Iterations
        await output.WriteIntAsync(iterations).ConfigureAwait(false);
    }

    /// <summary>
    /// Encrypts the data from the input stream and writes it to the output stream.
    /// Uses PBKDF2 for key derivation with the provided password and encryption parameters.
    /// </summary>
    /// <param name="input">The input stream containing data to encrypt.</param>
    /// <param name="output">The output stream where encrypted data will be written.</param>
    /// <param name="cipher">The cipher algorithm to use for encryption.</param>
    /// <param name="password">The password used for encryption key derivation.</param>
    /// <param name="iterations">The number of iterations for the PBKDF2 algorithm.</param>
    /// <param name="progress">Optional progress reporting interface.</param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous encryption operation.</returns>
    public async Task EncryptAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        string password,
        int iterations,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (input is null) throw new ArgumentNullException(nameof(input));
        if (output is null) throw new ArgumentNullException(nameof(output));
        if (password is null) throw new ArgumentNullException(nameof(password));
        if (iterations <= 0) throw new ArgumentOutOfRangeException(nameof(iterations));
        if (!Enum.IsDefined(typeof(Cipher), cipher)) throw new ArgumentOutOfRangeException(nameof(cipher));

        var pbkdf2Service = new Pbkdf2Service();

        // Get block cipher service from cipher enum
        var bcs = CipherUtils.GetBlockCipherService(cipher, CryptoHelpers.BcsFactory, CryptoHelpers.BcsEngineFactory);

        // Generate random salt
        var salt = RandomUtils.GenerateRandomBytes(16);
        var nonce = RandomUtils.GenerateRandomBytes(12);

        // Generate key from password and salt
        var key = pbkdf2Service.GenerateKey(32, password, salt, iterations);

        try
        {
            // Create GCM parameters for block cipher service
            var bcsParameters = CryptoHelpers.BcsParametersFactory.CreateGcmParameters(key, nonce);

            // Write header
            await WriteHeaderAsync(output, (byte)cipher, nonce, salt, iterations, cancellationToken).ConfigureAwait(false);

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
    /// <param name="input">The input stream containing the encrypted data.</param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
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
        if ((EncryptionType)typeValue != EncryptionType.Pbkdf2)
            throw new InvalidDataException("Invalid encryption type");

        // Version
        return await input.ReadByteAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Decrypts data from the input stream and writes the decrypted result to the output stream.
    /// Reads encryption parameters from the header and uses PBKDF2 for key derivation with the
    /// provided password.
    /// </summary>
    /// <param name="input">The input stream containing encrypted data.</param>
    /// <param name="output">The output stream where decrypted data will be written.</param>
    /// <param name="password">The password used for decryption key derivation.</param>
    /// <param name="progress">Optional progress reporting interface.</param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous decryption operation.</returns>
    /// <exception cref="InvalidDataException">Thrown when the encrypted data format is invalid.</exception>
    public async Task DecryptAsync(
        Stream input,
        Stream output,
        string password,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (input is null) throw new ArgumentNullException(nameof(input));
        if (output is null) throw new ArgumentNullException(nameof(output));
        if (password is null) throw new ArgumentNullException(nameof(password));

        var version = await ReadCommonPrefixAsync(input, cancellationToken).ConfigureAwait(false);

        switch (version)
        {
            case 0x01:
                await DecryptV1Async(input, output, password, progress, cancellationToken).ConfigureAwait(false);
                break;
            default:
                throw new InvalidDataException($"Unsupported version: 0x{version:x2}");
        }
    }

    private async Task DecryptV1Async(
        Stream input,
        Stream output,
        string password,
        IProgress<int>? progress,
        CancellationToken cancellationToken)
    {
        // Cipher
        var cipherValue = await input.ReadByteAsync().ConfigureAwait(false);
        var cipher = CryptoHelpers.ValidateCipher(cipherValue);

        // Nonce
        var nonce = await input.ReadBytesAsync(12).ConfigureAwait(false);

        // Salt
        var salt = await input.ReadBytesAsync(16).ConfigureAwait(false);

        // Iterations
        var iterations = await input.ReadIntAsync().ConfigureAwait(false);

        // Progress
        progress?.Report(37);

        // Get block cipher service from cipher enum
        var bcs = CipherUtils.GetBlockCipherService(cipher, CryptoHelpers.BcsFactory, CryptoHelpers.BcsEngineFactory);

        // Generate key from password and salt
        var pbkdf2Service = new Pbkdf2Service();
        var key = pbkdf2Service.GenerateKey(32, password, salt, iterations);

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
