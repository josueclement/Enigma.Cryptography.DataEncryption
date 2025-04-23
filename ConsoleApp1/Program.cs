using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.Cryptography.DataEncryption;
using Enigma.Extensions;
using Enigma.PQC;
using Enigma.PublicKey;

namespace ConsoleApp1;

static class Program
{
    static async Task Main(string[] args)
    {
        try
        {
            // await TestPbkdf2();
            // await TestArgon2();
            // await TestRsa();
            await TestMLKem();
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
    }

    static async Task TestPbkdf2()
    {
        var data = "This is a secret message".GetUtf8Bytes();
        
        using var inputEnc = new MemoryStream(data);
        using var outputEnc = new MemoryStream();
        
        var service = new Pbkdf2DataEncryptionService();
        await service.EncryptAsync(inputEnc, outputEnc, Cipher.Aes256Gcm, "test1234", 100000);
        
        var encData = outputEnc.ToArray();
        
        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();
        
        await service.DecryptAsync(inputDec, outputDec, "test1234");
        
        var decData = outputDec.ToArray(); 
    }
    
    static async Task TestArgon2()
    {
        var data = "This is a secret message".GetUtf8Bytes();
        
        using var inputEnc = new MemoryStream(data);
        using var outputEnc = new MemoryStream();
        
        var service = new Argon2DataEncryptionService();
        await service.EncryptAsync(inputEnc, outputEnc, Cipher.Aes256Gcm, "test1234".GetUtf8Bytes());
        
        var encData = outputEnc.ToArray();
        
        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();
        
        await service.DecryptAsync(inputDec, outputDec, "test1234".GetUtf8Bytes());
        
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
        await service.EncryptAsync(inputEnc, outputEnc, Cipher.Aes256Gcm, keyPair.Public);
        
        var encData = outputEnc.ToArray();
        
        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();
        
        await service.DecryptAsync(inputDec, outputDec, keyPair.Private);
        
        var decData = outputDec.ToArray(); 
    }
    
    static async Task TestMLKem()
    {
        var data = "This is a secret message".GetUtf8Bytes();

        var mlKem = new MLKemServiceFactory().CreateKem1024();
        var keyPair = mlKem.GenerateKeyPair();
        
        using var inputEnc = new MemoryStream(data);
        using var outputEnc = new MemoryStream();
        
        var service = new MLKemDataEncryptionService();
        await service.EncryptAsync(inputEnc, outputEnc, Cipher.Aes256Gcm, keyPair.Public);
        
        var encData = outputEnc.ToArray();
        
        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();
        
        await service.DecryptAsync(inputDec, outputDec, keyPair.Private);
        
        var decData = outputDec.ToArray();
    }
}