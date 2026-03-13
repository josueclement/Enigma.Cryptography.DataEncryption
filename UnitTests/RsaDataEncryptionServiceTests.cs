using Enigma.Cryptography.DataEncryption;
using Enigma.Cryptography.PublicKey;
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace UnitTests;

public class RsaDataEncryptionServiceTests
{
    private static readonly byte[] Data = Encoding.UTF8.GetBytes("This is a secret message");

    [Fact]
    public async Task RoundTrip_Aes256Gcm()
    {
        var ct = TestContext.Current.CancellationToken;
        var rsa = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = rsa.GenerateKeyPair(4096);

        var service = new RsaDataEncryptionService();
        using var input = new MemoryStream(Data);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, Cipher.Aes256Gcm, keyPair.Public, cancellationToken: ct);
        var encData = output.ToArray();

        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();
        await service.DecryptAsync(inputDec, outputDec, keyPair.Private, cancellationToken: ct);
        Assert.Equal(Data, outputDec.ToArray());
    }

    [Fact]
    public async Task RoundTrip_Twofish256Gcm()
    {
        var ct = TestContext.Current.CancellationToken;
        var rsa = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = rsa.GenerateKeyPair(4096);

        var service = new RsaDataEncryptionService();
        using var input = new MemoryStream(Data);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, Cipher.Twofish256Gcm, keyPair.Public, cancellationToken: ct);
        var encData = output.ToArray();

        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();
        await service.DecryptAsync(inputDec, outputDec, keyPair.Private, cancellationToken: ct);
        Assert.Equal(Data, outputDec.ToArray());
    }

    [Fact]
    public async Task RoundTrip_Serpent256Gcm()
    {
        var ct = TestContext.Current.CancellationToken;
        var rsa = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = rsa.GenerateKeyPair(4096);

        var service = new RsaDataEncryptionService();
        using var input = new MemoryStream(Data);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, Cipher.Serpent256Gcm, keyPair.Public, cancellationToken: ct);
        var encData = output.ToArray();

        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();
        await service.DecryptAsync(inputDec, outputDec, keyPair.Private, cancellationToken: ct);
        Assert.Equal(Data, outputDec.ToArray());
    }

    [Fact]
    public async Task RoundTrip_Camellia256Gcm()
    {
        var ct = TestContext.Current.CancellationToken;
        var rsa = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = rsa.GenerateKeyPair(4096);

        var service = new RsaDataEncryptionService();
        using var input = new MemoryStream(Data);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, Cipher.Camellia256Gcm, keyPair.Public, cancellationToken: ct);
        var encData = output.ToArray();

        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();
        await service.DecryptAsync(inputDec, outputDec, keyPair.Private, cancellationToken: ct);
        Assert.Equal(Data, outputDec.ToArray());
    }

    [Fact]
    public async Task WrongKey_ThrowsInvalidOperationException()
    {
        var ct = TestContext.Current.CancellationToken;
        var rsa = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = rsa.GenerateKeyPair(4096);
        var otherKeyPair = rsa.GenerateKeyPair(4096);

        var service = new RsaDataEncryptionService();
        using var input = new MemoryStream(Data);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, Cipher.Aes256Gcm, keyPair.Public, cancellationToken: ct);
        var encData = output.ToArray();

        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.DecryptAsync(inputDec, outputDec, otherKeyPair.Private, cancellationToken: ct));
    }

    [Fact]
    public async Task ComputeKeyFingerprint_Returns16Bytes()
    {
        var ct = TestContext.Current.CancellationToken;
        var rsa = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = rsa.GenerateKeyPair(4096);

        var service = new RsaDataEncryptionService();
        using var input = new MemoryStream([]);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, Cipher.Aes256Gcm, keyPair.Public, cancellationToken: ct);
        var encData = output.ToArray();

        // Header layout: [0xec, 0xde, type, version, cipher] = 5 bytes, then 16-byte fingerprint
        var fingerprint = encData[5..21];
        Assert.Equal(16, fingerprint.Length);
    }

    [Fact]
    public async Task EmptyData_RoundTrip()
    {
        var ct = TestContext.Current.CancellationToken;
        var rsa = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = rsa.GenerateKeyPair(4096);

        var service = new RsaDataEncryptionService();
        using var input = new MemoryStream([]);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, Cipher.Aes256Gcm, keyPair.Public, cancellationToken: ct);
        var encData = output.ToArray();

        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();
        await service.DecryptAsync(inputDec, outputDec, keyPair.Private, cancellationToken: ct);
        Assert.Equal([], outputDec.ToArray());
    }
}
