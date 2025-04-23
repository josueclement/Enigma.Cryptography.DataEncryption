using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.BlockCiphers;
using Enigma.Extensions;
using Enigma.KDF;
using Enigma.Utils;

namespace Enigma.Cryptography.DataEncryption;

/// <summary>
/// Provides encryption and decryption services using PBKDF2 for key derivation.
/// This service handles the encryption and decryption of data streams using password-based key derivation.
/// </summary>
public class Pbkdf2DataEncryptionService
{
    /// <summary>
    /// Writes the encryption header information to the output stream.
    /// </summary>
    /// <param name="output">The output stream to write the header to.</param>
    /// <param name="cipherValue">The byte value representing the cipher algorithm used.</param>
    /// <param name="salt">The salt bytes used for key derivation.</param>
    /// <param name="nonce">The nonce bytes used for encryption.</param>
    /// <param name="iterations">The number of iterations used in the PBKDF2 algorithm.</param>
    /// <returns>A task representing the asynchronous write operation.</returns>
    private async Task WriteHeaderAsync(Stream output, byte cipherValue, byte[] salt, byte[] nonce, int iterations)
    {
        await output.WriteBytesAsync([0xec, 0xde]);                 // Identifier
        await output.WriteByteAsync((byte)EncryptionTypes.PBKDF2);  // Type
        await output.WriteByteAsync(0x01);                          // Version
        await output.WriteByteAsync(cipherValue);                   // Cipher
        await output.WriteBytesAsync(salt);                         // Salt
        await output.WriteBytesAsync(nonce);                        // Nonce
        await output.WriteIntAsync(iterations);                     // Iterations 
    }
    
    /// <summary>
    /// Encrypts the data from the input stream and writes it to the output stream.
    /// </summary>
    /// <param name="input">The input stream containing data to encrypt.</param>
    /// <param name="output">The output stream where encrypted data will be written.</param>
    /// <param name="password">The password used for encryption key derivation.</param>
    /// <param name="iterations">The number of iterations for the PBKDF2 algorithm.</param>
    /// <param name="cipher">The cipher algorithm to use for encryption.</param>
    /// <param name="progress">Optional progress reporting interface.</param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous encryption operation.</returns>
    public async Task EncryptAsync(
        Stream input,
        Stream output,
        string password,
        int iterations,
        Ciphers cipher,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
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
        await WriteHeaderAsync(output, (byte)cipher, salt, nonce, iterations);
        
        // Encrypt data
        await bcs.EncryptAsync(input, output, bcsParameters, progress, cancellationToken);
        
        // Clear key from memory
        Array.Clear(key, 0, key.Length);
    }

    /// <summary>
    /// Reads and validates the encryption header from the input stream.
    /// </summary>
    /// <param name="input">The input stream containing the encrypted data.</param>
    /// <returns>A tuple containing the cipher algorithm, salt, nonce, and iterations extracted from the header.</returns>
    /// <exception cref="InvalidDataException">Thrown when the header is invalid or unsupported.</exception>
    private async Task<(Ciphers cipher, byte[] salt, byte[] nonce, int iterations)> ReadHeaderAsync(Stream input)
    {
        var header = await input.ReadBytesAsync(2);
        if (header[0] != 0xec || header[1] != 0xde)
            throw new InvalidDataException("Invalid header");
        
        var typeValue = await input.ReadByteAsync();
        if ((EncryptionTypes)typeValue != EncryptionTypes.PBKDF2)
            throw new InvalidDataException("Invalid encryption type");
        
        var version = await input.ReadByteAsync();
        if (version != 0x01)
            throw new InvalidDataException("Invalid version");
        
        var cipherValue = await input.ReadByteAsync();
        var cipher = (Ciphers)cipherValue; 
        
        var salt = await input.ReadBytesAsync(16);
        var nonce = await input.ReadBytesAsync(12);
        var iterations = await input.ReadIntAsync();
        
        return (cipher, salt, nonce, iterations);
    }
    
    /// <summary>
    /// Decrypts the data from the input stream and writes it to the output stream.
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
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var pbkdf2Service = new Pbkdf2Service();
        var bcsFactory = new BlockCipherServiceFactory();
        var bcsEngineFactory = new BlockCipherEngineFactory();
        var bcsParametersFactory = new BlockCipherParametersFactory();
        
        var (cipher, salt, nonce, iterations) = await ReadHeaderAsync(input);
        
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