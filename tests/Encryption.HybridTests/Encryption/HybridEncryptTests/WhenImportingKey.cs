using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using Encryption.Hybrid;
using Encryption.Hybrid.Asymmetric;
using Encryption.Hybrid.Hybrid;
using NUnit.Framework;

namespace Encryption.HybridTests.Encryption.HybridEncryptTests {
    public class WhenImportingKey
    {
        private HybridEncryption _hybridEncryption;

        public WhenImportingKey()
        {
            Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);

            var currentUser = WindowsIdentity.GetCurrent()
                                             .Name;

            var signatureContainer ="signature";
            var encryptionContainer ="encryption";

            var encryptionKey = RSAEncryption.CreateSecureContainer(encryptionContainer, currentUser);

            var encryptionPublicKey = encryptionKey.ExportKeyToXML(false);

            _hybridEncryption = HybridEncryption.Create(encryptionPublicKey, signatureContainer);
        }

        [Test]
        public void GivenEncryptionKeyBlob_WhenImportingKey_ThenImportsIVCorrectly()
        {
            RandomNumberGenerator random = new RNGCryptoServiceProvider();

            var data = File.ReadAllBytes("appsettings.json");
            var sessionKey = new byte[32];
            var iv = new byte[16];

            random.GetBytes(sessionKey);
            random.GetBytes(iv);

            (SessionKeyContainer key, byte[] encryptedData) encryptedResult = _hybridEncryption.EncryptData(sessionKey, data, iv);

            var key = encryptedResult.key;

            var keyBlob = key.ExportToBlob();

            var keyFromBlob = SessionKeyContainer.FromBlob(keyBlob);

            Assert.That(keyFromBlob.IV, Is.EqualTo(key.IV));
        }

        [Test]
        public void GivenEncryptionKeyBlob_WhenImportingKey_ThenImportsHMACHashCorrectly()
        {
            RandomNumberGenerator random = new RNGCryptoServiceProvider();

            var data =File.ReadAllBytes("appsettings.json");
            var sessionKey = new byte[32];
            var iv = new byte[16];

            random.GetBytes(sessionKey);
            random.GetBytes(iv);

            (SessionKeyContainer key, byte[] encryptedData) encryptedResult = _hybridEncryption.EncryptData(sessionKey, data, iv);

            var key = encryptedResult.key;

            var keyBlob = key.ExportToBlob();

            var keyFromBlob = SessionKeyContainer.FromBlob(keyBlob);

            Assert.That(keyFromBlob.HMACHash, Is.EqualTo(key.HMACHash));
        }

        [Test]
        public void GivenEncryptionKeyBlob_WhenImportingKey_ThenImportsSessionKeyCorrectly()
        {
            RandomNumberGenerator random = new RNGCryptoServiceProvider();

            var data = File.ReadAllBytes("appsettings.json");
            var sessionKey = new byte[32];
            var iv = new byte[16];

            random.GetBytes(sessionKey);
            random.GetBytes(iv);

            (SessionKeyContainer key, byte[] encryptedData) encryptedResult = _hybridEncryption.EncryptData(sessionKey, data, iv);

            var key = encryptedResult.key;

            var keyBlob = key.ExportToBlob();

            var keyFromBlob = SessionKeyContainer.FromBlob(keyBlob);

            Assert.That(keyFromBlob.SessionKey, Is.EqualTo(key.SessionKey));
        }

        [Test]
        public void GivenEncryptionKeyBlob_WhenImportingKey_ThenDecryptsSessionKeyCorrectly()
        {
            RandomNumberGenerator random = new RNGCryptoServiceProvider();

            var data = File.ReadAllBytes("appsettings.json");
            var sessionKey = new byte[32];
            var iv = new byte[16];

            random.GetBytes(sessionKey);
            random.GetBytes(iv);

            (SessionKeyContainer key, byte[] encryptedData) encryptedResult = _hybridEncryption.EncryptData(sessionKey, data, iv);

            var key = encryptedResult.key;

            var keyBlob = key.ExportToBlob();

            var keyFromBlob = SessionKeyContainer.FromBlob(keyBlob);
            var rsaEcryption = RSAEncryption.LoadContainer("encryption");

            var decryptedSessionKey = rsaEcryption.DecryptData(keyFromBlob.SessionKey);

            Assert.That(sessionKey, Is.EqualTo(decryptedSessionKey));
        }
    }
}