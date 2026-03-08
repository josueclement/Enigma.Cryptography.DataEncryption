using Enigma.Cryptography.DataEncryption;
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace UnitTests;

public class Argon2DataEncryptionServiceTests
{
    private static readonly byte[] Data = Encoding.UTF8.GetBytes("This is a secret message");
    private static readonly byte[] Password = Encoding.UTF8.GetBytes("test1234");
    private static readonly byte[] WrongPassword = Encoding.UTF8.GetBytes("wrong-password");

    private static async Task<byte[]> Encrypt(Cipher cipher, byte[] password, CancellationToken ct)
    {
        var service = new Argon2DataEncryptionService();
        using var input = new MemoryStream(Data);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, cipher, password, cancellationToken: ct);
        return output.ToArray();
    }

    private static async Task<byte[]> Decrypt(byte[] encData, byte[] password, CancellationToken ct)
    {
        var service = new Argon2DataEncryptionService();
        using var input = new MemoryStream(encData);
        using var output = new MemoryStream();
        await service.DecryptAsync(input, output, password, cancellationToken: ct);
        return output.ToArray();
    }

    [Fact]
    public async Task RoundTrip_Aes256Gcm()
    {
        var ct = TestContext.Current.CancellationToken;
        var enc = await Encrypt(Cipher.Aes256Gcm, Password, ct);
        var dec = await Decrypt(enc, Password, ct);
        Assert.Equal(Data, dec);
    }

    [Fact]
    public async Task RoundTrip_Twofish256Gcm()
    {
        var ct = TestContext.Current.CancellationToken;
        var enc = await Encrypt(Cipher.Twofish256Gcm, Password, ct);
        var dec = await Decrypt(enc, Password, ct);
        Assert.Equal(Data, dec);
    }

    [Fact]
    public async Task RoundTrip_Serpent256Gcm()
    {
        var ct = TestContext.Current.CancellationToken;
        var enc = await Encrypt(Cipher.Serpent256Gcm, Password, ct);
        var dec = await Decrypt(enc, Password, ct);
        Assert.Equal(Data, dec);
    }

    [Fact]
    public async Task RoundTrip_Camellia256Gcm()
    {
        var ct = TestContext.Current.CancellationToken;
        var enc = await Encrypt(Cipher.Camellia256Gcm, Password, ct);
        var dec = await Decrypt(enc, Password, ct);
        Assert.Equal(Data, dec);
    }

    [Fact]
    public async Task WrongPassword_ThrowsException()
    {
        var ct = TestContext.Current.CancellationToken;
        var enc = await Encrypt(Cipher.Aes256Gcm, Password, ct);
        await Assert.ThrowsAnyAsync<Exception>(() => Decrypt(enc, WrongPassword, ct));
    }

    [Fact]
    public async Task EmptyData_RoundTrip()
    {
        var ct = TestContext.Current.CancellationToken;
        var service = new Argon2DataEncryptionService();
        using var input = new MemoryStream([]);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, Cipher.Aes256Gcm, Password, cancellationToken: ct);
        var encData = output.ToArray();

        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();
        await service.DecryptAsync(inputDec, outputDec, Password, cancellationToken: ct);
        Assert.Equal([], outputDec.ToArray());
    }
}
