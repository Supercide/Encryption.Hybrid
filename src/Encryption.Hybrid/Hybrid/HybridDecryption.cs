using System.Security.Cryptography;
using Encryption.Hybrid.Asymmetric;
using Encryption.Hybrid.Symmetric;

namespace Encryption.Hybrid.Hybrid {
    public class HybridDecryption : IHybridDecryption
    {
        private readonly IAsymmetricKeyEncryption _asymmetricKeyEncryption;
        private readonly ISymmetricKeyEncryption _symmetricKeyEncryption;
        private readonly IDigitalSignature _digitalSignature;

        protected HybridDecryption(IAsymmetricKeyEncryption asymmetricKeyEncryption,
                                   ISymmetricKeyEncryption symmetricKeyEncryption,
                                   IDigitalSignature digitalSignature)
        {
            _asymmetricKeyEncryption = asymmetricKeyEncryption;
            _symmetricKeyEncryption = symmetricKeyEncryption;
            _digitalSignature = digitalSignature;
        }

        public byte[] DecryptData(SessionKeyContainer sessionKeyContainer, byte[] data)
        {
            var decryptedSessionKey = _asymmetricKeyEncryption.DecryptData(sessionKeyContainer.SessionKey);

            using (var hmac = new HMACSHA256(decryptedSessionKey))
            {
                var hmacToCheck = hmac.ComputeHash(data);

                if (!Compare(sessionKeyContainer.HMACHash, hmacToCheck))
                {
                    throw new CryptographicException("HMAC signatures do not match");
                }

                if (!_digitalSignature.VerifyData(sessionKeyContainer.HMACHash, sessionKeyContainer.Signature))
                {
                    throw new CryptographicException("Signatures cannot be verified");
                }
            }

            var decryptedData = _symmetricKeyEncryption.Decrypt(data, decryptedSessionKey, sessionKeyContainer.IV);

            return decryptedData;
        }

        public static HybridDecryption Create(string containerName, string signaturePublicKey)
        {
            return new HybridDecryption(RSAEncryption.LoadContainer(containerName), 
                                        new AESEncryption(), 
                                        RSAEncryption.CreateWithKey(signaturePublicKey));
        }

        private static bool Compare(byte[] array1, byte[] array2)
        {
            var result = array1.Length == array2.Length;

            for (var i = 0; i < array1.Length && i < array2.Length; ++i)
            {
                result &= array1[i] == array2[i];
            }

            return result;
        }
    }
}