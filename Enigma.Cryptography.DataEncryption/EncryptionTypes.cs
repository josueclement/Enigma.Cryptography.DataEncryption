namespace Enigma.Cryptography.DataEncryption;

public enum EncryptionTypes : byte
{
    PBKDF2 = 0x01,
    ARGON2 = 0x02,
    RSA = 0x03,
    MLKEM = 0x04
}