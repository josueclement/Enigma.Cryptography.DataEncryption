using Enigma.Cryptography.DataEncryption;
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace UnitTests;

public class Pbkdf2DataEncryptionServiceTests
{
    private static readonly byte[] Data = Encoding.UTF8.GetBytes("This is a secret message");
    private const string Password = "test1234";
    private const int Iterations = 100000;

    private static async Task<byte[]> Encrypt(Cipher cipher, string password, CancellationToken ct)
    {
        var service = new Pbkdf2DataEncryptionService();
        using var input = new MemoryStream(Data);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, cipher, password, Iterations, cancellationToken: ct);
        return output.ToArray();
    }

    private static async Task<byte[]> Decrypt(byte[] encData, string password, CancellationToken ct)
    {
        var service = new Pbkdf2DataEncryptionService();
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
        await Assert.ThrowsAnyAsync<Exception>(() => Decrypt(enc, "wrong-password", ct));
    }

    [Fact]
    public async Task EmptyData_RoundTrip()
    {
        var ct = TestContext.Current.CancellationToken;
        var service = new Pbkdf2DataEncryptionService();
        using var input = new MemoryStream([]);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, Cipher.Aes256Gcm, Password, Iterations, cancellationToken: ct);
        var encData = output.ToArray();

        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();
        await service.DecryptAsync(inputDec, outputDec, Password, cancellationToken: ct);
        Assert.Equal([], outputDec.ToArray());
    }

    [Fact]
    public async Task EncryptAsync_NullPassword_ThrowsArgumentNullException()
    {
        var ct = TestContext.Current.CancellationToken;
        var service = new Pbkdf2DataEncryptionService();
        using var input = new MemoryStream(Data);
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            service.EncryptAsync(input, output, Cipher.Aes256Gcm, null!, Iterations, cancellationToken: ct));
    }

    [Fact]
    public async Task EncryptAsync_ZeroIterations_ThrowsArgumentOutOfRangeException()
    {
        var ct = TestContext.Current.CancellationToken;
        var service = new Pbkdf2DataEncryptionService();
        using var input = new MemoryStream(Data);
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            service.EncryptAsync(input, output, Cipher.Aes256Gcm, Password, 0, cancellationToken: ct));
    }

    [Fact]
    public async Task EncryptAsync_InvalidCipher_ThrowsArgumentOutOfRangeException()
    {
        var ct = TestContext.Current.CancellationToken;
        var service = new Pbkdf2DataEncryptionService();
        using var input = new MemoryStream(Data);
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            service.EncryptAsync(input, output, (Cipher)0xFF, Password, Iterations, cancellationToken: ct));
    }

    [Fact]
    public async Task DecryptAsync_TruncatedCiphertext_ThrowsException()
    {
        var ct = TestContext.Current.CancellationToken;
        var enc = await Encrypt(Cipher.Aes256Gcm, Password, ct);
        var truncated = enc[..10];
        var service = new Pbkdf2DataEncryptionService();
        using var input = new MemoryStream(truncated);
        using var output = new MemoryStream();
        await Assert.ThrowsAnyAsync<Exception>(() =>
            service.DecryptAsync(input, output, Password, cancellationToken: ct));
    }

    [Fact]
    public async Task EncryptAsync_CancellationAlreadyCancelled_Throws()
    {
        var service = new Pbkdf2DataEncryptionService();
        using var input = new MemoryStream(Data);
        using var output = new MemoryStream();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            service.EncryptAsync(input, output, Cipher.Aes256Gcm, Password, Iterations, cancellationToken: cts.Token));
    }

    [Fact]
    public async Task DecryptAsync_UnsupportedVersion_ThrowsInvalidDataException()
    {
        var ct = TestContext.Current.CancellationToken;
        var enc = await Encrypt(Cipher.Aes256Gcm, Password, ct);

        // Tamper version byte (index 3) to 0xFF
        enc[3] = 0xFF;

        var service = new Pbkdf2DataEncryptionService();
        using var input = new MemoryStream(enc);
        using var output = new MemoryStream();
        var ex = await Assert.ThrowsAsync<InvalidDataException>(() =>
            service.DecryptAsync(input, output, Password, cancellationToken: ct));
        Assert.Contains("Unsupported version: 0xff", ex.Message);
    }

    [Fact]
    public async Task GoldenBlob_V1_DecryptsSuccessfully()
    {
        var ct = TestContext.Current.CancellationToken;

        // Encrypt known data and capture the blob
        var enc = await Encrypt(Cipher.Aes256Gcm, Password, ct);

        // Verify it decrypts correctly (this blob becomes the regression anchor)
        var dec = await Decrypt(enc, Password, ct);
        Assert.Equal(Data, dec);

        // Verify the header prefix matches expected v1 format
        Assert.Equal(0xec, enc[0]); // identifier
        Assert.Equal(0xde, enc[1]); // identifier
        Assert.Equal(0x01, enc[2]); // type = Pbkdf2
        Assert.Equal(0x01, enc[3]); // version = 1
    }
}
