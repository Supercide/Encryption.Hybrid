namespace Encryption.Hybrid.Hybrid {
    public interface IHybridDecryption
    {
        byte[] DecryptData(SessionKeyContainer sessionKeyContainer, byte[] data);
    }
}