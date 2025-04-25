using Enigma.BlockCiphers;
using Enigma.Extensions;
using Enigma.KDF;
using Enigma.Utils;
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
        await output.WriteBytesAsync([0xec, 0xde]);
        
        // Type
        await output.WriteByteAsync((byte)EncryptionType.Pbkdf2);
        
        // Version
        await output.WriteByteAsync(0x01);
        
        // Cipher
        await output.WriteByteAsync(cipherValue);
        
        // Nonce
        await output.WriteBytesAsync(nonce);
        
        // Salt
        await output.WriteBytesAsync(salt);
        
        // Iterations
        await output.WriteIntAsync(iterations);
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
        
        var pbkdf2Service = new Pbkdf2Service();
        var bcsFactory = new BlockCipherServiceFactory();
        var bcsEngineFactory = new BlockCipherEngineFactory();
        var bcsParametersFactory = new BlockCipherParametersFactory();
        
        // Get block cipher service from cipher enum
        var bcs = CipherUtils.GetBlockCipherService(cipher, bcsFactory, bcsEngineFactory);

        // Generate random salt
        var salt = RandomUtils.GenerateRandomBytes(16);
        var nonce = RandomUtils.GenerateRandomBytes(12);
        
        // Generate key from password and salt
        var key = pbkdf2Service.GenerateKey(32, password, salt, iterations);
        
        // Create GCM parameters for block cipher service
        var bcsParameters = bcsParametersFactory.CreateGcmParameters(key, nonce);
        
        // Write header
        await WriteHeaderAsync(output, (byte)cipher, nonce, salt, iterations, cancellationToken);
        
        // Encrypt data
        await bcs.EncryptAsync(input, output, bcsParameters, progress, cancellationToken);
        
        // Clear key from memory
        Array.Clear(key, 0, key.Length);
    }

    /// <summary>
    /// Reads and parses the encryption header from the input stream to extract
    /// the parameters needed for decryption.
    /// </summary>
    /// <param name="input">The input stream containing the encrypted data.</param>
    /// <param name="progress">Optional progress reporting interface.</param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A tuple containing the cipher algorithm, nonce, salt, and iterations extracted from the header.</returns>
    /// <exception cref="InvalidDataException">Thrown when the header is invalid or unsupported.</exception>
    private async Task<(Cipher cipher, byte[] nonce, byte[] salt, int iterations)> ReadHeaderAsync(
        Stream input,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        
        // Identifier
        var header = await input.ReadBytesAsync(2);
        if (header[0] != 0xec || header[1] != 0xde)
            throw new InvalidDataException("Invalid header");
        
        // Type
        var typeValue = await input.ReadByteAsync();
        if ((EncryptionType)typeValue != EncryptionType.Pbkdf2)
            throw new InvalidDataException("Invalid encryption type");
        
        // Version
        var version = await input.ReadByteAsync();
        if (version != 0x01)
            throw new InvalidDataException("Invalid version");
        
        // Cipher
        var cipherValue = await input.ReadByteAsync();
        var cipher = (Cipher)cipherValue; 
        
        // Nonce
        var nonce = await input.ReadBytesAsync(12);
        
        // Salt
        var salt = await input.ReadBytesAsync(16);
        
        // Iterations
        var iterations = await input.ReadIntAsync();
        
        // Progress
        progress?.Report(37);
        
        return (cipher, nonce, salt, iterations);
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
        var pbkdf2Service = new Pbkdf2Service();
        var bcsFactory = new BlockCipherServiceFactory();
        var bcsEngineFactory = new BlockCipherEngineFactory();
        var bcsParametersFactory = new BlockCipherParametersFactory();
        
        // Read header
        var (cipher, nonce, salt, iterations) = await ReadHeaderAsync(input, progress, cancellationToken);
        
        // Get block cipher service from cipher enum
        var bcs = CipherUtils.GetBlockCipherService(cipher, bcsFactory, bcsEngineFactory);
        
        // Generate key from password and salt
        var key = pbkdf2Service.GenerateKey(32, password, salt, iterations);
        
        // Create GCM parameters for block cipher service
        var bcsParameters = bcsParametersFactory.CreateGcmParameters(key, nonce);
        
        // Decrypt data
        await bcs.DecryptAsync(input, output, bcsParameters, progress, cancellationToken);
        
        // Clear key from memory
        Array.Clear(key, 0, key.Length);
    }
}