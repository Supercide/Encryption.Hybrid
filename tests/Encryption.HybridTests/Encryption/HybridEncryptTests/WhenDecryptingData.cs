using System.Security.Cryptography;
using System.Security.Principal;
using Encryption.Hybrid;
using Encryption.Hybrid.Asymmetric;
using Encryption.Hybrid.Hybrid;
using NUnit.Framework;

namespace Encryption.HybridTests.Encryption.HybridEncryptTests
{
    public class WhenDecryptingData
    {
        [Test]
        public void GivenEncryptingData_WhenDecryptingData_ThenDataIsDecrypted()
        {
            var currentUser = WindowsIdentity.GetCurrent()
                                             .Name;

            var target = RSAEncryption.LoadSecureContainer(new RSAContainer("target"), currentUser);
            var signatureContainer = RSAEncryption.LoadSecureContainer("signatureContainer", currentUser);
            var signaturePublicKey = signatureContainer.ExportKeyToXML(false);
            var targetPublicKey = target.ExportKeyToXML(false);

            HybridEncryption hybridEncryption = HybridEncryption.CreateEncryption(targetPublicKey, "signatureContainer");
            HybridDecryption hybridDecryption = HybridDecryption.CreateDecryption("target", signaturePublicKey);

            RandomNumberGenerator random = new RNGCryptoServiceProvider();

            var data = new byte[512];
            var sessionKey = new byte[32];
            var iv = new byte[16];

            random.GetBytes(sessionKey);
            random.GetBytes(iv);
            random.GetBytes(data);

            (SessionKeyContainer key, byte[] encryptedData) encryptedResult = hybridEncryption.EncryptData(sessionKey, data, iv);



            var decryptedData = hybridDecryption.DecryptData(encryptedResult.key, encryptedResult.encryptedData);

            Assert.That(decryptedData, Is.EqualTo(data));
        }

        [Test]
        public void GivenEncryptingData_WhenDecryptingData_FromImportedKey_ThenDataIsDecrypted()
        {
            var currentUser = WindowsIdentity.GetCurrent()
                                             .Name;

            var target = RSAEncryption.LoadSecureContainer("target", currentUser);
            var signatureContainer = RSAEncryption.LoadSecureContainer("signatureContainer", currentUser);
            var signaturePublicKey = signatureContainer.ExportKeyToXML(false);
            var targetPublicKey = target.ExportKeyToXML(false);

            HybridEncryption hybridEncryption = HybridEncryption.CreateEncryption(targetPublicKey, "signatureContainer");
            HybridDecryption hybridDecryption = HybridDecryption.CreateDecryption("target", signaturePublicKey);

            RandomNumberGenerator random = new RNGCryptoServiceProvider();

            var data = new byte[512];
            var sessionKey = new byte[32];
            var iv = new byte[16];

            random.GetBytes(sessionKey);
            random.GetBytes(iv);
            random.GetBytes(data);

            (SessionKeyContainer key, byte[] encryptedData) encryptedResult = hybridEncryption.EncryptData(sessionKey, data, iv);

            var keyBlob = encryptedResult.key.ExportToBlob();

            var keyFromBlob = SessionKeyContainer.FromBlob(keyBlob);

            var decryptedData = hybridDecryption.DecryptData(keyFromBlob, encryptedResult.encryptedData);

            Assert.That(decryptedData, Is.EqualTo(data));
        }
    }
}
