namespace Encryption.Hybrid.NumberGenerators {
    public interface IGenerateRandomBytes
    {
        byte[] Generate(int length);
    }
}