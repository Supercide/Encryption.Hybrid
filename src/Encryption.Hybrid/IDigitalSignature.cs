namespace Encryption.Hybrid.Asymmetric {
    public interface IDigitalSignature
    {
        byte[] SignData(byte[] data);

        bool VerifyData(byte[] data, byte[] signature);
    }
}