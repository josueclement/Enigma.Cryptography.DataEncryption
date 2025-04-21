using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Extensions;
using Enigma.PublicKey;
using Org.BouncyCastle.Crypto;

namespace Enigma.Cryptography.DataEncryption;

public class RsaDataEncryptionService
{
    public async Task EncryptAsync(
        Stream input,
        Stream output,
        AsymmetricKeyParameter publicKey,
        DataEncryptionCipher cipher,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var rsaService = new PublicKeyServiceFactory().CreateRsaService();

        await output.WriteBytesAsync([0xec, 0xde]); // Header
        await output.WriteByteAsync((byte)DataEncryptionType.RSA); // Type
        await output.WriteByteAsync(0x01); // Version
        // TODO: add encrypted key + nonce + ...
    }

    public async Task DecryptAsync(
        Stream input,
        Stream output,
        AsymmetricKeyParameter privateKey,
        DataEncryptionCipher cipher,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        
    }
}