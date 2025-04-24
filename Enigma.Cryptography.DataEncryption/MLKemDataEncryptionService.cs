using Enigma.BlockCiphers;
using Enigma.Extensions;
using Enigma.PQC;
using Enigma.Utils;
using Org.BouncyCastle.Crypto;
using System.IO;
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
    /// Writes the encryption header to the output stream. The header contains encryption
    /// parameters that will be used later during decryption.
    /// </summary>
    /// <param name="output">The stream to write the header to</param>
    /// <param name="cipherValue">The byte representing the cipher algorithm used</param>
    /// <param name="encapsulation">The ML-KEM encapsulation data</param>
    /// <param name="nonce">The nonce/initialization vector used for encryption</param>
    /// <returns>A task representing the asynchronous operation</returns>
    private async Task WriteHeaderAsync(Stream output, byte cipherValue, byte[] encapsulation, byte[] nonce)
    {
        // Identifier
        await output.WriteBytesAsync([0xec, 0xde]);
        
        // Type
        await output.WriteByteAsync((byte)EncryptionType.MLKem);
        
        // Version
        await output.WriteByteAsync(0x01);
        
        // Cipher
        await output.WriteByteAsync(cipherValue);
        
        // Nonce
        await output.WriteBytesAsync(nonce);
        
        // Encapsulation
        await output.WriteLengthValueAsync(encapsulation);
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

        // Encapsulate secret key using public key
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
    /// Reads and parses the encryption header from the input stream to extract
    /// the parameters needed for decryption.
    /// </summary>
    /// <param name="input">The stream to read the header from</param>
    /// <returns>A tuple containing the cipher type, encapsulation data, and nonce</returns>
    /// <exception cref="InvalidDataException">Thrown when header validation fails</exception>
    private async Task<(Cipher cipher, byte[] encapsulation, byte[] nonce)> ReadHeaderAsync(Stream input)
    {
        // Identifier
        var header = await input.ReadBytesAsync(2);
        if (header[0] != 0xec || header[1] != 0xde)
            throw new InvalidDataException("Invalid header");
        
        // Type
        var typeValue = await input.ReadByteAsync();
        if ((EncryptionType)typeValue != EncryptionType.MLKem)
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
        
        // Encapsulation
        var encapsulation = await input.ReadLengthValueAsync();
        
        return (cipher, encapsulation, nonce);
    }
    
    /// <summary>
    /// Decrypts data from the input stream to the output stream using ML-KEM and a symmetric block cipher.
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

        // Read header
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