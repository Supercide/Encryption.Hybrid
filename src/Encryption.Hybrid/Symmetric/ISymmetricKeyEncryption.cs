namespace Encryption.Hybrid.Symmetric {
    public interface ISymmetricKeyEncryption
    {
        byte[] Encrypt(byte[] data, byte[] key, byte[] iv);

        byte[] Decrypt(byte[] data, byte[] key, byte[] iv);
    }
}