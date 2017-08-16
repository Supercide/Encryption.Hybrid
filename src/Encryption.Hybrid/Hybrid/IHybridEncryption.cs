namespace Encryption.Hybrid.Hybrid {
    public interface IHybridEncryption
    {
        (SessionKeyContainer key, byte[] encryptedData) EncryptData(byte[] sessionKey, byte[] data, byte[] Iv);
    }
}