using Enigma.Cryptography.DataEncryption;
using Enigma.Cryptography.PublicKey;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace UnitTests;

public class RsaDataEncryptionServiceTests
{
    private static readonly byte[] Data = Encoding.UTF8.GetBytes("This is a secret message");

    private static async Task<byte[]> Encrypt(Cipher cipher)
    {
        var rsa = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = rsa.GenerateKeyPair(4096);
        var service = new RsaDataEncryptionService();
        using var input = new MemoryStream(Data);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, cipher, keyPair.Public);
        return output.ToArray();
    }

    [Fact]
    public async Task RoundTrip_Aes256Gcm()
    {
        var rsa = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = rsa.GenerateKeyPair(4096);

        var service = new RsaDataEncryptionService();
        using var input = new MemoryStream(Data);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, Cipher.Aes256Gcm, keyPair.Public);
        var encData = output.ToArray();

        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();
        await service.DecryptAsync(inputDec, outputDec, keyPair.Private);
        Assert.Equal(Data, outputDec.ToArray());
    }

    [Fact]
    public async Task RoundTrip_Twofish256Gcm()
    {
        var rsa = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = rsa.GenerateKeyPair(4096);

        var service = new RsaDataEncryptionService();
        using var input = new MemoryStream(Data);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, Cipher.Twofish256Gcm, keyPair.Public);
        var encData = output.ToArray();

        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();
        await service.DecryptAsync(inputDec, outputDec, keyPair.Private);
        Assert.Equal(Data, outputDec.ToArray());
    }

    [Fact]
    public async Task WrongKey_ThrowsInvalidOperationException()
    {
        var rsa = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = rsa.GenerateKeyPair(4096);
        var otherKeyPair = rsa.GenerateKeyPair(4096);

        var service = new RsaDataEncryptionService();
        using var input = new MemoryStream(Data);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, Cipher.Aes256Gcm, keyPair.Public);
        var encData = output.ToArray();

        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.DecryptAsync(inputDec, outputDec, otherKeyPair.Private));
    }

    [Fact]
    public async Task ComputeKeyFingerprint_Returns16Bytes()
    {
        var rsa = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = rsa.GenerateKeyPair(4096);

        var service = new RsaDataEncryptionService();
        using var input = new MemoryStream([]);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, Cipher.Aes256Gcm, keyPair.Public);
        var encData = output.ToArray();

        // Header layout: [0xec, 0xde, type, version, cipher] = 5 bytes, then 16-byte fingerprint
        var fingerprint = encData[5..21];
        Assert.Equal(16, fingerprint.Length);
    }
}
