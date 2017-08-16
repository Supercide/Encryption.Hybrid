using System.Security.Cryptography;

namespace Encryption.Hybrid.NumberGenerators
{
    public class RNGCryptoRandomBytesGenerator : IGenerateRandomBytes
    {
        public byte[] Generate(int length)
        {
            using (var rand = new RNGCryptoServiceProvider())
            {
                var randomBytesbuffer = new byte[length];

                rand.GetBytes(randomBytesbuffer);

                return randomBytesbuffer;
            }
        }
    }
}
