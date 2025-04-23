using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.BlockCiphers;
using Enigma.Extensions;
using Enigma.PQC;
using Enigma.Utils;
using Org.BouncyCastle.Crypto;

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
    /// Writes the encryption header to the output stream.
    /// The header contains metadata necessary for decryption, including:
    /// - Magic identifier (0xECDE)
    /// - Encryption type (ML-KEM)
    /// - Version information
    /// - Cipher algorithm identifier
    /// - ML-KEM encapsulation data
    /// - Nonce (initialization vector)
    /// </summary>
    /// <param name="output">The stream to write the header to</param>
    /// <param name="cipherValue">The byte representing the cipher algorithm used</param>
    /// <param name="encapsulation">The ML-KEM encapsulation data</param>
    /// <param name="nonce">The nonce/initialization vector used for encryption</param>
    /// <returns>A task representing the asynchronous operation</returns>
    private async Task WriteHeaderAsync(Stream output, byte cipherValue, byte[] encapsulation, byte[] nonce)
    {
        await output.WriteBytesAsync([0xec, 0xde]);                 // Identifier
        await output.WriteByteAsync((byte)EncryptionType.MLKem);   // Type
        await output.WriteByteAsync(0x01);                          // Version
        await output.WriteByteAsync(cipherValue);                   // Cipher
        await output.WriteLengthValueAsync(encapsulation);          // Encapsulation
        await output.WriteBytesAsync(nonce);                        // Nonce 
    }
    
    /// <summary>
    /// Encrypts data from the input stream to the output stream using ML-KEM key encapsulation
    /// combined with a symmetric block cipher.
    /// 
    /// The process:
    /// 1. Generates an ML-KEM encapsulation and shared secret using the provided public key
    /// 2. Uses the shared secret as the key for the symmetric cipher
    /// 3. Writes header information to the output stream
    /// 4. Encrypts the input stream data using the chosen cipher in GCM mode
    /// 5. Securely clears sensitive data from memory
    /// </summary>
    /// <param name="input">The stream containing plaintext data to encrypt</param>
    /// <param name="output">The stream where encrypted data will be written</param>
    /// <param name="publicKey">The recipient's ML-KEM public key</param>
    /// <param name="cipher">The symmetric cipher algorithm to use</param>
    /// <param name="progress">Optional progress reporting</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>A task representing the asynchronous encryption operation</returns>
    public async Task EncryptAsync(
        Stream input,
        Stream output,
        AsymmetricKeyParameter publicKey,
        Cipher cipher,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var mlKemService = new MLKemServiceFactory().CreateKem1024();
        var bcsFactory = new BlockCipherServiceFactory();
        var bcsEngineFactory = new BlockCipherEngineFactory();
        var bcsParametersFactory = new BlockCipherParametersFactory();

        // Get block cipher service from cipher enum
        var bcs = CipherUtils.GetBlockCipherService(cipher, bcsFactory, bcsEngineFactory);
        
        // Generate random nonce
        var nonce = RandomUtils.GenerateRandomBytes(12);

        var (encapsulation, secret) = mlKemService.Encapsulate(publicKey);
        
        // Create GCM parameters for block cipher service
        var bcsParameters = bcsParametersFactory.CreateGcmParameters(secret, nonce);
        
        // Write header
        await WriteHeaderAsync(output, (byte)cipher, encapsulation, nonce);
        
        // Encrypt data
        await bcs.EncryptAsync(input, output, bcsParameters, progress, cancellationToken);
        
        // Clear key from memory
        Array.Clear(secret, 0, secret.Length);
    }
    
    /// <summary>
    /// Reads and validates the encryption header from the input stream.
    /// Extracts the cipher type, encapsulation data, and nonce needed for decryption.
    /// 
    /// Performs validation checks on:
    /// - Magic identifier (0xECDE)
    /// - Encryption type (ML-KEM)
    /// - Version information
    /// </summary>
    /// <param name="input">The stream to read the header from</param>
    /// <returns>A tuple containing the cipher type, encapsulation data, and nonce</returns>
    /// <exception cref="InvalidDataException">Thrown when header validation fails</exception>
    private async Task<(Cipher cipher, byte[] encapsulation, byte[] nonce)> ReadHeaderAsync(Stream input)
    {
        var header = await input.ReadBytesAsync(2);
        if (header[0] != 0xec || header[1] != 0xde)
            throw new InvalidDataException("Invalid header");
        
        var typeValue = await input.ReadByteAsync();
        if ((EncryptionType)typeValue != EncryptionType.MLKem)
            throw new InvalidDataException("Invalid encryption type");
        
        var version = await input.ReadByteAsync();
        if (version != 0x01)
            throw new InvalidDataException("Invalid version");
        
        var cipherValue = await input.ReadByteAsync();
        var cipher = (Cipher)cipherValue; 
        
        var encapsulation = await input.ReadLengthValueAsync();
        var nonce = await input.ReadBytesAsync(12);
        
        return (cipher, encapsulation, nonce);
    }
    
    /// <summary>
    /// Decrypts data from the input stream to the output stream using ML-KEM and a symmetric block cipher.
    /// 
    /// The process:
    /// 1. Reads header information from the input stream
    /// 2. Decapsulates the shared secret using the provided private key and encapsulation data from the header
    /// 3. Configures the block cipher with the shared secret and nonce from the header
    /// 4. Decrypts the input stream data using the identified cipher in GCM mode
    /// 5. Securely clears sensitive data from memory
    /// </summary>
    /// <param name="input">The stream containing encrypted data to decrypt</param>
    /// <param name="output">The stream where decrypted data will be written</param>
    /// <param name="privateKey">The recipient's ML-KEM private key</param>
    /// <param name="progress">Optional progress reporting</param>
    /// <param name="cancellationToken">Token to cancel the operation</param>
    /// <returns>A task representing the asynchronous decryption operation</returns>
    public async Task DecryptAsync(
        Stream input,
        Stream output,
        AsymmetricKeyParameter privateKey,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var mlKemService = new MLKemServiceFactory().CreateKem1024();
        var bcsFactory = new BlockCipherServiceFactory();
        var bcsEngineFactory = new BlockCipherEngineFactory();
        var bcsParametersFactory = new BlockCipherParametersFactory();

        var (cipher, encapsulation, nonce) = await ReadHeaderAsync(input);
        
        // Get block cipher service from cipher enum
        var bcs = CipherUtils.GetBlockCipherService(cipher, bcsFactory, bcsEngineFactory);
        
        // Decapsulate secret key using private key
        var secret = mlKemService.Decapsulate(encapsulation, privateKey);
        
        // Create GCM parameters for block cipher service
        var bcsParameters = bcsParametersFactory.CreateGcmParameters(secret, nonce);
        
        // Decrypt data
        await bcs.DecryptAsync(input, output, bcsParameters, progress, cancellationToken);
        
        // Clear key from memory
        Array.Clear(secret, 0, secret.Length);
    }
}