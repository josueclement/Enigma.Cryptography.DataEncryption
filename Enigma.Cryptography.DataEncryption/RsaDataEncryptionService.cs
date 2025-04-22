using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.BlockCiphers;
using Enigma.Extensions;
using Enigma.PublicKey;
using Enigma.Utils;
using Org.BouncyCastle.Crypto;

namespace Enigma.Cryptography.DataEncryption;

public class RsaDataEncryptionService
{
    public async Task EncryptAsync(
        Stream input,
        Stream output,
        AsymmetricKeyParameter publicKey,
        Ciphers cipher,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
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

        // Write headers
        await output.WriteBytesAsync([0xec, 0xde]); // Header
        await output.WriteByteAsync((byte)EncryptionTypes.RSA); // Type
        await output.WriteByteAsync(0x01); // Version
        await output.WriteByteAsync((byte)cipher); // Cipher
        await output.WriteTagLengthValueAsync((byte)HeaderTags.EncryptedKey, encKey); // Encrypted key
        await output.WriteTagLengthValueAsync((byte)HeaderTags.Nonce, nonce); // Nonce
        
        // Encrypt data
        await bcs.EncryptAsync(input, output, bcsParameters, progress, cancellationToken);
        
        // Clear key from memory
        Array.Clear(key, 0, key.Length);
    }

    public async Task DecryptAsync(
        Stream input,
        Stream output,
        AsymmetricKeyParameter privateKey,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var rsaService = new PublicKeyServiceFactory().CreateRsaService();
        var bcsFactory = new BlockCipherServiceFactory();
        var bcsEngineFactory = new BlockCipherEngineFactory();
        var bcsParametersFactory = new BlockCipherParametersFactory();
        
        var header = await input.ReadBytesAsync(2);
        if (header[0] != 0xec || header[1] != 0xde)
            throw new InvalidDataException("Invalid header");
        
        var typeValue = await input.ReadByteAsync();
        if ((EncryptionTypes)typeValue != EncryptionTypes.RSA)
            throw new InvalidDataException("Invalid encryption type");
        
        var version = await input.ReadByteAsync();
        if (version != 0x01)
            throw new InvalidDataException("Invalid version");
        
        var cipherValue = await input.ReadByteAsync();
        var cipher = (Ciphers)cipherValue;

        var (_, encKey) = await input.ReadTagLengthValueAsync();
        var (_, nonce) = await input.ReadTagLengthValueAsync();
        
        // Decrypt key with private key
        var key = rsaService.Decrypt(encKey, privateKey);
        
        // Get block cipher service from cipher enum
        var bcs = CipherUtils.GetBlockCipherService(cipher, bcsFactory, bcsEngineFactory);
        
        // Create GCM parameters for block cipher service
        var bcsParameters = bcsParametersFactory.CreateGcmParameters(key, nonce); 
        
        await bcs.DecryptAsync(input, output, bcsParameters, progress, cancellationToken);
        
        Array.Clear(key, 0, key.Length);
    }
}