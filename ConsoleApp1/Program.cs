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