namespace Enigma.Cryptography.DataEncryption;

public enum Ciphers : byte
{
    AES_256_GCM = 0x01,
    TWOFISH_256_GCM = 0x02,
    SERPENT_256_GCM = 0x03,
    CAMELLIA_256_GCM = 0x04,
}