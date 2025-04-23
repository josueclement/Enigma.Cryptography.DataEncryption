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
/// Provides data encryption and decryption services using Argon2 for key derivation
/// and block ciphers for the encryption operation. This implementation includes custom
/// header formatting to store encryption parameters.
/// </summary>
public class Argon2DataEncryptionService
{
    /// <summary>
    /// Writes the encryption header to the output stream. The header contains encryption
    /// parameters that will be used later during decryption.
    /// </summary>
    /// <param name="output">The stream to write the header to</param>
    /// <param name="cipherValue">The cipher algorithm identifier</param>
    /// <param name="salt">The salt used for key derivation</param>
    /// <param name="nonce">The nonce (initialization vector) used for encryption</param>
    /// <param name="iterations">The number of iterations for Argon2</param>
    /// <param name="parallelism">The parallelism factor for Argon2</param>
    /// <param name="memoryPowOfTwo">The memory cost factor (power of two) for Argon2</param>
    /// <returns>A task representing the asynchronous write operation</returns>
    private async Task WriteHeaderAsync(
        Stream output,
        byte cipherValue,
        byte[] salt,
        byte[] nonce,
        int iterations,
        int parallelism,
        int memoryPowOfTwo)
    {
        // Identifier
        await output.WriteBytesAsync([0xec, 0xde]);
        
        // Type
        await output.WriteByteAsync((byte)EncryptionType.Argon2);
        
        // Version
        await output.WriteByteAsync(0x01);
        
        // Cipher
        await output.WriteByteAsync(cipherValue);
        
        // Salt
        await output.WriteBytesAsync(salt);
        
        // Nonce
        await output.WriteBytesAsync(nonce);
        
        // Iterations
        await output.WriteIntAsync(iterations);
        
        // Parallelism
        await output.WriteIntAsync(parallelism);
        
        // Memory pow of two
        await output.WriteIntAsync(memoryPowOfTwo);
    }
    
    /// <summary>
    /// Encrypts data from the input stream and writes the encrypted result to the output stream.
    /// Uses Argon2 for key derivation with the provided password and encryption parameters.
    /// </summary>
    /// <param name="input">The stream containing data to encrypt</param>
    /// <param name="output">The stream to write encrypted data to</param>
    /// <param name="cipher">The cipher algorithm to use for encryption</param>
    /// <param name="password">The password to derive the encryption key from</param>
    /// <param name="iterations">The number of iterations for Argon2 (default: 10)</param>
    /// <param name="parallelism">The parallelism factor for Argon2 (default: 4)</param>
    /// <param name="memoryPowOfTwo">The memory cost factor (power of two) for Argon2 (default: 16)</param>
    /// <param name="progress">Optional progress reporter</param>
    /// <param name="cancellationToken">Optional cancellation token</param>
    /// <returns>A task representing the asynchronous encryption operation</returns>
    public async Task EncryptAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        byte[] password,
        int iterations = 10,
        int parallelism = 4,
        int memoryPowOfTwo = 16,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var argon2Service = new Argon2Service();
        var bcsFactory = new BlockCipherServiceFactory();
        var bcsEngineFactory = new BlockCipherEngineFactory();
        var bcsParametersFactory = new BlockCipherParametersFactory();
        
        // Get block cipher service from cipher enum
        var bcs = CipherUtils.GetBlockCipherService(cipher, bcsFactory, bcsEngineFactory);

        // Generate random salt
        var salt = RandomUtils.GenerateRandomBytes(16);
        var nonce = RandomUtils.GenerateRandomBytes(12);
        
        // Generate key from password and salt
        var key = argon2Service.GenerateKey(32, password, salt, iterations, parallelism, memoryPowOfTwo);
        
        // Create GCM parameters for block cipher service
        var bcsParameters = bcsParametersFactory.CreateGcmParameters(key, nonce);
        
        // Write header
        await WriteHeaderAsync(output, (byte)cipher, salt, nonce, iterations, parallelism, memoryPowOfTwo);
        
        // Encrypt data
        await bcs.EncryptAsync(input, output, bcsParameters, progress, cancellationToken);
        
        // Clear key from memory
        Array.Clear(key, 0, key.Length);
    }

    /// <summary>
    /// Reads and parses the encryption header from the input stream to extract
    /// the parameters needed for decryption.
    /// </summary>
    /// <param name="input">The stream to read the header from</param>
    /// <returns>A tuple containing the cipher algorithm and encryption parameters</returns>
    /// <exception cref="InvalidDataException">Thrown when the header is invalid</exception>
    private async Task<(Cipher cipher, byte[] salt, byte[] nonce, int iterations, int parallelism, int memoryPowOfTwo)>
        ReadHeaderAsync(Stream input)
    {
        // Identifier
        var header = await input.ReadBytesAsync(2);
        if (header[0] != 0xec || header[1] != 0xde)
            throw new InvalidDataException("Invalid header");
        
        // Type
        var typeValue = await input.ReadByteAsync();
        if ((EncryptionType)typeValue != EncryptionType.Argon2)
            throw new InvalidDataException("Invalid encryption type");
        
        // Version
        var version = await input.ReadByteAsync();
        if (version != 0x01)
            throw new InvalidDataException("Invalid version");
        
        // Cipher
        var cipherValue = await input.ReadByteAsync();
        var cipher = (Cipher)cipherValue; 
        
        // Salt
        var salt = await input.ReadBytesAsync(16);
        
        // Nonce
        var nonce = await input.ReadBytesAsync(12);
        
        // Iterations
        var iterations = await input.ReadIntAsync();
        
        // Parallelism
        var parallelism = await input.ReadIntAsync();
        
        // Memory pow of two
        var memoryPowOfTwo = await input.ReadIntAsync();
        
        return (cipher, salt, nonce, iterations, parallelism, memoryPowOfTwo);
    }

    /// <summary>
    /// Decrypts data from the input stream and writes the decrypted result to the output stream.
    /// Reads encryption parameters from the header and uses Argon2 for key derivation with the
    /// provided password.
    /// </summary>
    /// <param name="input">The stream containing encrypted data</param>
    /// <param name="output">The stream to write decrypted data to</param>
    /// <param name="password">The password used to derive the decryption key</param>
    /// <param name="progress">Optional progress reporter</param>
    /// <param name="cancellationToken">Optional cancellation token</param>
    /// <returns>A task representing the asynchronous decryption operation</returns>
    public async Task DecryptAsync(
        Stream input,
        Stream output,
        byte[] password,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var argon2Service = new Argon2Service();
        var bcsFactory = new BlockCipherServiceFactory();
        var bcsEngineFactory = new BlockCipherEngineFactory();
        var bcsParametersFactory = new BlockCipherParametersFactory();
        
        // Read header and extract encryption parameters
        var (cipher, salt, nonce, iterations, parallelism, memoryPowOfTwo) = await ReadHeaderAsync(input);
        
        // Get block cipher service from cipher enum
        var bcs = CipherUtils.GetBlockCipherService(cipher, bcsFactory, bcsEngineFactory);
        
        // Generate key from password and salt
        var key = argon2Service.GenerateKey(32, password, salt, iterations, parallelism, memoryPowOfTwo);
        
        // Create GCM parameters for block cipher service
        var bcsParameters = bcsParametersFactory.CreateGcmParameters(key, nonce);
        
        // Decrypt data
        await bcs.DecryptAsync(input, output, bcsParameters, progress, cancellationToken);
        
        // Clear key from memory
        Array.Clear(key, 0, key.Length);
    }
}