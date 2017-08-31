using System.Security.Cryptography;
using Encryption.Hybrid.Asymmetric;
using Encryption.Hybrid.Symmetric;

namespace Encryption.Hybrid.Hybrid {

    public class HybridEncryption : IHybridEncryption
    {
        private readonly IAsymmetricKeyEncryption _asymmetricKeyEncryption;
        private readonly ISymmetricKeyEncryption _symmetricKeyEncryption;
        private readonly IDigitalSignature _digitalSignature;

        protected HybridEncryption(IAsymmetricKeyEncryption asymmetricKeyEncryption, 
                                ISymmetricKeyEncryption symmetricKeyEncryption, 
                                IDigitalSignature digitalSignature)
        {
            _asymmetricKeyEncryption = asymmetricKeyEncryption;
            _symmetricKeyEncryption = symmetricKeyEncryption;
            _digitalSignature = digitalSignature;
        }

        public (SessionKeyContainer key, byte[] encryptedData) EncryptData(byte[] sessionKey, byte[] data, byte[] Iv)
        {
            var encryptedData = _symmetricKeyEncryption.Encrypt(data, sessionKey, Iv);

            var encryptedSessionKey = _asymmetricKeyEncryption.EncryptData(sessionKey);

            byte[] hmacHash;

            using (var hmac = new HMACSHA256(sessionKey))
            {
                hmacHash = hmac.ComputeHash(encryptedData);
            }

            var signature = _digitalSignature.SignData(hmacHash);

            return (new SessionKeyContainer(encryptedSessionKey, Iv, hmacHash, signature), encryptedData);
        }

        public static HybridEncryption Create(string publicKey, RSAContainer signatureContainer)
        {
            return new HybridEncryption(RSAEncryption.FromPublicKey(publicKey),
                                        new AESEncryption(), 
                                        RSAEncryption.LoadContainer(signatureContainer));
        }
    }

    public class RSAContainer
    {
        public RSAContainer(string name)
        {
            Name = name;
        }

        public readonly string Name;
    }
}