using Enigma.Cryptography.DataEncryption;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace UnitTests;

public class Argon2DataEncryptionServiceTests
{
    private static readonly byte[] Data = Encoding.UTF8.GetBytes("This is a secret message");
    private static readonly byte[] Password = Encoding.UTF8.GetBytes("test1234");
    private static readonly byte[] WrongPassword = Encoding.UTF8.GetBytes("wrong-password");

    private static async Task<byte[]> Encrypt(Cipher cipher, byte[] password)
    {
        var service = new Argon2DataEncryptionService();
        using var input = new MemoryStream(Data);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, cipher, password);
        return output.ToArray();
    }

    private static async Task<byte[]> Decrypt(byte[] encData, byte[] password)
    {
        var service = new Argon2DataEncryptionService();
        using var input = new MemoryStream(encData);
        using var output = new MemoryStream();
        await service.DecryptAsync(input, output, password);
        return output.ToArray();
    }

    [Fact]
    public async Task RoundTrip_Aes256Gcm()
    {
        var enc = await Encrypt(Cipher.Aes256Gcm, Password);
        var dec = await Decrypt(enc, Password);
        Assert.Equal(Data, dec);
    }

    [Fact]
    public async Task RoundTrip_Twofish256Gcm()
    {
        var enc = await Encrypt(Cipher.Twofish256Gcm, Password);
        var dec = await Decrypt(enc, Password);
        Assert.Equal(Data, dec);
    }

    [Fact]
    public async Task RoundTrip_Serpent256Gcm()
    {
        var enc = await Encrypt(Cipher.Serpent256Gcm, Password);
        var dec = await Decrypt(enc, Password);
        Assert.Equal(Data, dec);
    }

    [Fact]
    public async Task RoundTrip_Camellia256Gcm()
    {
        var enc = await Encrypt(Cipher.Camellia256Gcm, Password);
        var dec = await Decrypt(enc, Password);
        Assert.Equal(Data, dec);
    }

    [Fact]
    public async Task WrongPassword_ThrowsException()
    {
        var enc = await Encrypt(Cipher.Aes256Gcm, Password);
        await Assert.ThrowsAnyAsync<Exception>(() => Decrypt(enc, WrongPassword));
    }

    [Fact]
    public async Task EmptyData_RoundTrip()
    {
        var service = new Argon2DataEncryptionService();
        using var input = new MemoryStream([]);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, Cipher.Aes256Gcm, Password);
        var encData = output.ToArray();

        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();
        await service.DecryptAsync(inputDec, outputDec, Password);
        Assert.Equal([], outputDec.ToArray());
    }
}
