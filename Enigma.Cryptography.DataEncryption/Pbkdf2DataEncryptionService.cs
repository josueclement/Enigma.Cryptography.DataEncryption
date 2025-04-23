using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.BlockCiphers;
using Enigma.Extensions;
using Enigma.KDF;
using Enigma.Utils;

namespace Enigma.Cryptography.DataEncryption;

public class Pbkdf2DataEncryptionService
{
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
        
        // Write headers
        await output.WriteBytesAsync([0xec, 0xde]); // Header
        await output.WriteByteAsync((byte)EncryptionTypes.PBKDF2); // Type
        await output.WriteByteAsync(0x01); // Version
        await output.WriteByteAsync((byte)cipher); // Cipher
        await output.WriteBytesAsync(salt); // Salt
        await output.WriteBytesAsync(nonce); // Nonce
        await output.WriteIntAsync(iterations); // Iterations
        
        // Encrypt data
        await bcs.EncryptAsync(input, output, bcsParameters, progress, cancellationToken);
        
        // Clear key from memory
        Array.Clear(key, 0, key.Length);
    }
    
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
        
        // Get block cipher service from cipher enum
        var bcs = CipherUtils.GetBlockCipherService(cipher, bcsFactory, bcsEngineFactory);
        
        var salt = await input.ReadBytesAsync(16);
        var nonce = await input.ReadBytesAsync(12);
        var iterations = await input.ReadIntAsync();
        
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