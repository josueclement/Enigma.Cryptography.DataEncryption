using Enigma.Cryptography.DataEncryption;
using Enigma.Cryptography.Extensions;
using Enigma.Cryptography.PQC;
using Enigma.Cryptography.PublicKey;
using System.IO;
using System.Threading.Tasks;
using System;

namespace ConsoleApp1;

static class Program
{
    static async Task Main()
    {
        try
        {
            await TestPbkdf2();
            await TestArgon2();
            await TestRsa();
            await TestMLKem();
            await TestRsaMatchesFingerprint();
            await TestMLKemMatchesFingerprint();
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
    }

    static bool CheckValidity(byte[] data, byte[] decryptedData)
    {
        if (data.Length != decryptedData.Length)
            return false;
        for (int i = 0; i < data.Length; i++)
            if (data[i] != decryptedData[i])
                return false;
        return true;
    }

    static async Task TestPbkdf2()
    {
        Console.Write("Pbkdf2DataEncryptionService: ");
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
        
        Console.WriteLine(CheckValidity(data, decData) ? "OK" : "FAILED" );
    }
    
    static async Task TestArgon2()
    {
        Console.Write("Argon2DataEncryptionService: ");
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
        
        Console.WriteLine(CheckValidity(data, decData) ? "OK" : "FAILED" );
    }

    static async Task TestRsa()
    {
        Console.Write("RsaDataEncryptionService: ");
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

        Console.WriteLine(CheckValidity(data, decData) ? "OK" : "FAILED" );
    }

    // ReSharper disable once InconsistentNaming
    static async Task TestMLKem()
    {
        Console.Write("MLKemDataEncryptionService: ");
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

        Console.WriteLine(CheckValidity(data, decData) ? "OK" : "FAILED" );
    }

    static async Task TestRsaMatchesFingerprint()
    {
        Console.Write("RsaDataEncryptionService.MatchesFingerprint: ");
        var data = "This is a secret message".GetUtf8Bytes();

        var rsa = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = rsa.GenerateKeyPair(4096);
        var otherKeyPair = rsa.GenerateKeyPair(4096);

        using var inputEnc = new MemoryStream(data);
        using var outputEnc = new MemoryStream();

        var service = new RsaDataEncryptionService();
        await service.EncryptAsync(inputEnc, outputEnc, Cipher.Aes256Gcm, keyPair.Public);

        var encData = outputEnc.ToArray();

        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();

        await service.DecryptAsync(inputDec, outputDec, keyPair.Private);

        using var inputDec2 = new MemoryStream(encData);
        using var outputDec2 = new MemoryStream();

        var threw = false;
        try { await service.DecryptAsync(inputDec2, outputDec2, otherKeyPair.Private); }
        catch (InvalidOperationException) { threw = true; }

        Console.WriteLine(threw ? "OK" : "FAILED");
    }

    // ReSharper disable once InconsistentNaming
    static async Task TestMLKemMatchesFingerprint()
    {
        Console.Write("MLKemDataEncryptionService.MatchesFingerprint: ");
        var data = "This is a secret message".GetUtf8Bytes();

        var mlKem = new MLKemServiceFactory().CreateKem1024();
        var keyPair = mlKem.GenerateKeyPair();
        var otherKeyPair = mlKem.GenerateKeyPair();

        using var inputEnc = new MemoryStream(data);
        using var outputEnc = new MemoryStream();

        var service = new MLKemDataEncryptionService();
        await service.EncryptAsync(inputEnc, outputEnc, Cipher.Aes256Gcm, keyPair.Public);

        var encData = outputEnc.ToArray();

        using var inputDec = new MemoryStream(encData);
        using var outputDec = new MemoryStream();

        await service.DecryptAsync(inputDec, outputDec, keyPair.Private);

        using var inputDec2 = new MemoryStream(encData);
        using var outputDec2 = new MemoryStream();

        var threw = false;
        try { await service.DecryptAsync(inputDec2, outputDec2, otherKeyPair.Private); }
        catch (InvalidOperationException) { threw = true; }

        Console.WriteLine(threw ? "OK" : "FAILED");
    }
}