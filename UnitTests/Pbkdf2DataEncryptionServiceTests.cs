using Enigma.Cryptography.DataEncryption;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace UnitTests;

public class Pbkdf2DataEncryptionServiceTests
{
    private static readonly byte[] Data = Encoding.UTF8.GetBytes("This is a secret message");
    private const string Password = "test1234";
    private const int Iterations = 100000;

    private static async Task<byte[]> Encrypt(Cipher cipher, string password)
    {
        var service = new Pbkdf2DataEncryptionService();
        using var input = new MemoryStream(Data);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, cipher, password, Iterations);
        return output.ToArray();
    }

    private static async Task<byte[]> Decrypt(byte[] encData, string password)
    {
        var service = new Pbkdf2DataEncryptionService();
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
        await Assert.ThrowsAnyAsync<Exception>(() => Decrypt(enc, "wrong-password"));
    }

    [Fact]
    public async Task EmptyData_RoundTrip()
    {
        var service = new Pbkdf2DataEncryptionService();
        using var input = new MemoryStream([]);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, Cipher.Aes256Gcm, Password, Iterations);
        var encData = output.ToArray();

        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();
        await service.DecryptAsync(inputDec, outputDec, Password);
        Assert.Equal([], outputDec.ToArray());
    }
}
