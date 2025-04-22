namespace Enigma.Cryptography.DataEncryption;

public enum HeaderTags : byte
{
    EncryptedKey = 0x01,
    IV = 0x02,
    Nonce = 0x03,
    Salt = 0x04,
    Iterations = 0x05,
    Argon2Parallelism = 0x06,
    Argon2MemoryPowOfTwo = 0x07,
    Argon2Variant = 0x08,
    Argon2Version = 0x09,
    KemEncapsulation = 0x0a
}