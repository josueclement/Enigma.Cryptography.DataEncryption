using Enigma.Cryptography.DataEncryption;
using Enigma.Cryptography.PQC;
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace UnitTests;

// ReSharper disable once InconsistentNaming
public class MLKemDataEncryptionServiceTests
{
    private static readonly byte[] Data = Encoding.UTF8.GetBytes("This is a secret message");

    [Fact]
    public async Task RoundTrip_Aes256Gcm()
    {
        var ct = TestContext.Current.CancellationToken;
        var mlKem = new MLKemServiceFactory().CreateKem1024();
        var keyPair = mlKem.GenerateKeyPair();

        var service = new MLKemDataEncryptionService();
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
        var mlKem = new MLKemServiceFactory().CreateKem1024();
        var keyPair = mlKem.GenerateKeyPair();

        var service = new MLKemDataEncryptionService();
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
        var mlKem = new MLKemServiceFactory().CreateKem1024();
        var keyPair = mlKem.GenerateKeyPair();

        var service = new MLKemDataEncryptionService();
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
        var mlKem = new MLKemServiceFactory().CreateKem1024();
        var keyPair = mlKem.GenerateKeyPair();

        var service = new MLKemDataEncryptionService();
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
        var mlKem = new MLKemServiceFactory().CreateKem1024();
        var keyPair = mlKem.GenerateKeyPair();
        var otherKeyPair = mlKem.GenerateKeyPair();

        var service = new MLKemDataEncryptionService();
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
        var mlKem = new MLKemServiceFactory().CreateKem1024();
        var keyPair = mlKem.GenerateKeyPair();

        var service = new MLKemDataEncryptionService();
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
        var mlKem = new MLKemServiceFactory().CreateKem1024();
        var keyPair = mlKem.GenerateKeyPair();

        var service = new MLKemDataEncryptionService();
        using var input = new MemoryStream([]);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, Cipher.Aes256Gcm, keyPair.Public, cancellationToken: ct);
        var encData = output.ToArray();

        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();
        await service.DecryptAsync(inputDec, outputDec, keyPair.Private, cancellationToken: ct);
        Assert.Equal([], outputDec.ToArray());
    }

    [Fact]
    public async Task DecryptAsync_UnsupportedVersion_ThrowsInvalidDataException()
    {
        var ct = TestContext.Current.CancellationToken;
        var mlKem = new MLKemServiceFactory().CreateKem1024();
        var keyPair = mlKem.GenerateKeyPair();

        var service = new MLKemDataEncryptionService();
        using var input = new MemoryStream(Data);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, Cipher.Aes256Gcm, keyPair.Public, cancellationToken: ct);
        var enc = output.ToArray();

        // Tamper version byte (index 3) to 0xFF
        enc[3] = 0xFF;

        using var inputDec = new MemoryStream(enc);
        using var outputDec = new MemoryStream();
        var ex = await Assert.ThrowsAsync<InvalidDataException>(() =>
            service.DecryptAsync(inputDec, outputDec, keyPair.Private, cancellationToken: ct));
        Assert.Contains("Unsupported version: 0xff", ex.Message);
    }

    [Fact]
    public async Task GoldenBlob_V2_DecryptsSuccessfully()
    {
        var ct = TestContext.Current.CancellationToken;
        var mlKem = new MLKemServiceFactory().CreateKem1024();
        var keyPair = mlKem.GenerateKeyPair();

        var service = new MLKemDataEncryptionService();
        using var input = new MemoryStream(Data);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, Cipher.Aes256Gcm, keyPair.Public, cancellationToken: ct);
        var enc = output.ToArray();

        // Verify it decrypts correctly
        using var inputDec = new MemoryStream(enc);
        using var outputDec = new MemoryStream();
        await service.DecryptAsync(inputDec, outputDec, keyPair.Private, cancellationToken: ct);
        Assert.Equal(Data, outputDec.ToArray());

        // Verify the header prefix matches expected v2 format
        Assert.Equal(0xec, enc[0]); // identifier
        Assert.Equal(0xde, enc[1]); // identifier
        Assert.Equal(0x04, enc[2]); // type = MLKem
        Assert.Equal(0x02, enc[3]); // version = 2
    }
}
