using System.IO;
using System.Threading.Tasks;
using Enigma.Cryptography.DataEncryption;
using Enigma.Extensions;
using Enigma.PublicKey;

namespace ConsoleApp1;

static class Program
{
    static async Task Main(string[] args)
    {
        // await TestPbkdf2();
        await TestRsa();
    }

    static async Task TestPbkdf2()
    {
        var data = "This is a secret message".GetUtf8Bytes();
        
        using var inputEnc = new MemoryStream(data);
        using var outputEnc = new MemoryStream();
        
        var service = new Pbkdf2DataEncryptionService();
        await service.EncryptAsync(inputEnc, outputEnc, "test1234", 100000, Ciphers.AES_256_GCM);
        
        var encData = outputEnc.ToArray();
        
        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();
        
        await service.DecryptAsync(inputDec, outputDec, "test1234");
        
        var decData = outputDec.ToArray(); 
    }

    static async Task TestRsa()
    {
        var data = "This is a secret message".GetUtf8Bytes();

        var rsa = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = rsa.GenerateKeyPair(4096);
        
        using var inputEnc = new MemoryStream(data);
        using var outputEnc = new MemoryStream();

        var service = new RsaDataEncryptionService();
        await service.EncryptAsync(inputEnc, outputEnc, keyPair.Public, Ciphers.AES_256_GCM);
        
        var encData = outputEnc.ToArray();
        
        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();
        
        await service.DecryptAsync(inputDec, outputDec, keyPair.Private);
        
        var decData = outputDec.ToArray(); 
    }
}