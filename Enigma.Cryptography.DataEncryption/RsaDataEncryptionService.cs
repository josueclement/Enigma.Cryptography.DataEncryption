﻿using Enigma.Cryptography.BlockCiphers;
using Enigma.Cryptography.Extensions;
using Enigma.Cryptography.PublicKey;
using Enigma.Cryptography.Utils;
using Org.BouncyCastle.Crypto;
using System.IO;
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
    /// <summary>
    /// Writes the encryption header to the output stream. The header contains encryption
    /// parameters that will be used later during decryption.
    /// </summary>
    /// <param name="output">The stream to write the header information to.</param>
    /// <param name="cipherValue">The byte value representing the cipher algorithm used.</param>
    /// <param name="encKey">The encrypted symmetric key.</param>
    /// <param name="nonce">The initialization vector (nonce) for the symmetric encryption.</param>
    /// <param name="cancellationToken">Optional token to monitor for cancellation requests.</param>
    /// <returns>A task representing the asynchronous write operation.</returns>
    private async Task WriteHeaderAsync(
        Stream output,
        byte cipherValue,
        byte[] encKey,
        byte[] nonce,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        
        // Identifier
        await output.WriteBytesAsync([0xec, 0xde]);
        
        // Type
        await output.WriteByteAsync((byte)EncryptionType.Rsa);
        
        // Version
        await output.WriteByteAsync(0x01);
        
        // Cipher
        await output.WriteByteAsync(cipherValue);
        
        // Nonce
        await output.WriteBytesAsync(nonce);
        
        // Encrypted key
        await output.WriteLengthValueAsync(encKey);
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
        
        var rsaService = new PublicKeyServiceFactory().CreateRsaService();
        var bcsFactory = new BlockCipherServiceFactory();
        var bcsEngineFactory = new BlockCipherEngineFactory();
        var bcsParametersFactory = new BlockCipherParametersFactory();

        // Get block cipher service from cipher enum
        var bcs = CipherUtils.GetBlockCipherService(cipher, bcsFactory, bcsEngineFactory);
        
        // Generate random key and nonce
        var key = RandomUtils.GenerateRandomBytes(32);
        var nonce = RandomUtils.GenerateRandomBytes(12);
        
        // Create GCM parameters for block cipher service
        var bcsParameters = bcsParametersFactory.CreateGcmParameters(key, nonce);
        
        // Encrypt key with public key
        var encKey = rsaService.Encrypt(key, publicKey);

        // Write header
        await WriteHeaderAsync(output, (byte)cipher, encKey, nonce, cancellationToken);
        
        // Encrypt data
        await bcs.EncryptAsync(input, output, bcsParameters, progress, cancellationToken);
        
        // Clear key from memory
        Array.Clear(key, 0, key.Length);
    }

    /// <summary>
    /// Reads and parses the encryption header from the input stream to extract
    /// the parameters needed for decryption.
    /// </summary>
    /// <param name="input">The stream containing the encrypted data.</param>
    /// <param name="progress">Optional progress reporting mechanism.</param>
    /// <param name="cancellationToken">Optional token to monitor for cancellation requests.</param>
    /// <returns>A tuple containing the cipher algorithm, encrypted key, and nonce extracted from the header.</returns>
    /// <exception cref="InvalidDataException">Thrown when the header format is invalid.</exception>
    private async Task<(Cipher cipher, byte[] encKey, byte[] nonce)> ReadHeaderAsync(
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
        if ((EncryptionType)typeValue != EncryptionType.Rsa)
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
        
        // Encrypted key
        var encKey = await input.ReadLengthValueAsync();
        
        // Progress
        progress?.Report(21 + encKey.Length);
        
        return (cipher, encKey, nonce);
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
    public async Task DecryptAsync(
        Stream input,
        Stream output,
        AsymmetricKeyParameter privateKey,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        
        var rsaService = new PublicKeyServiceFactory().CreateRsaService();
        var bcsFactory = new BlockCipherServiceFactory();
        var bcsEngineFactory = new BlockCipherEngineFactory();
        var bcsParametersFactory = new BlockCipherParametersFactory();
        
        // Read header
        var (cipher, encKey, nonce) = await ReadHeaderAsync(input, progress, cancellationToken);
        
        // Get block cipher service from cipher enum
        var bcs = CipherUtils.GetBlockCipherService(cipher, bcsFactory, bcsEngineFactory);

        // Decrypt key with private key
        var key = rsaService.Decrypt(encKey, privateKey);
        
        // Create GCM parameters for block cipher service
        var bcsParameters = bcsParametersFactory.CreateGcmParameters(key, nonce); 
        
        // Decrypt data
        await bcs.DecryptAsync(input, output, bcsParameters, progress, cancellationToken);
        
        // Clear key from memory
        Array.Clear(key, 0, key.Length);
    }
}