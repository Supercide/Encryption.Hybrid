using System.Security.Cryptography;
using System.Security.Principal;
using Encryption.Hybrid.Asymmetric;
using Encryption.Hybrid.Hybrid;
using NUnit.Framework;

namespace Encryption.HybridTests.Encryption.HybridEncryptTests
{
    public class WhenEncryptingData
    {
        private readonly HybridEncryption _hybridEncryption;

        public WhenEncryptingData()
        {
            var currentUser = WindowsIdentity.GetCurrent()
                                             .Name;

            var signatureContainer = new RSAContainer("signature");
            var encryptionContainer = new RSAContainer("encryption");

            var encryptionKey = RSAEncryption.LoadSecureContainer(encryptionContainer, currentUser);
            
            var encryptionPublicKey = encryptionKey.ExportKeyToXML(false);

            _hybridEncryption = HybridEncryption.Create(encryptionPublicKey, signatureContainer);
        }

        [Test]
        public void GivenRandomData_WhenEncryptingData_ThenDataIsEncrypted()
        {
            RandomNumberGenerator random = new RNGCryptoServiceProvider();

            var data = new byte[512];
            var sessionKey = new byte[32];
            var iv = new byte[16];

            random.GetBytes(sessionKey);
            random.GetBytes(iv);
            random.GetBytes(data);

            var encryptedResult = _hybridEncryption.EncryptData(sessionKey, data, iv);

            Assert.That(encryptedResult.encryptedData, Is.Not.EqualTo(data));
        }

        [Test]
        public void GivenRandomData_WhenEncryptingData_ThenIVIsReturned()
        {
           RandomNumberGenerator random = new RNGCryptoServiceProvider();

            var data = new byte[512];
            var sessionKey = new byte[32];
            var iv = new byte[16];

            random.GetBytes(sessionKey);
            random.GetBytes(iv);
            random.GetBytes(data);

            var encryptedResult = _hybridEncryption.EncryptData(sessionKey, data, iv);

            Assert.That(encryptedResult.key.IV, Is.Not.Empty);
        }

        [Test]
        public void GivenRandomData_WhenEncryptingData_ThenHMACHashIsReturned()
        {
            RandomNumberGenerator random = new RNGCryptoServiceProvider();

            var data = new byte[512];
            var sessionKey = new byte[32];
            var iv = new byte[16];

            random.GetBytes(sessionKey);
            random.GetBytes(iv);
            random.GetBytes(data);

            var encryptedResult = _hybridEncryption.EncryptData(sessionKey, data, iv);

            Assert.That(encryptedResult.key.HMACHash, Is.Not.Empty);
        }

        [Test]
        public void GivenRandomData_WhenEncryptingData_ThenSessionKeyIsReturned()
        {
            RandomNumberGenerator random = new RNGCryptoServiceProvider();

            var data = new byte[512];
            var sessionKey = new byte[32];
            var iv = new byte[16];

            random.GetBytes(sessionKey);
            random.GetBytes(iv);
            random.GetBytes(data);

            var encryptedResult = _hybridEncryption.EncryptData(sessionKey, data, iv);

            Assert.That(encryptedResult.key.SessionKey, Is.Not.Empty);
        }
    }
}
