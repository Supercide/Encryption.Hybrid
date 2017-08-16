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
        public WhenImportingKey()
        {
            Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);
        }

        [Test]
        public void GivenEncryptionKeyBlob_WhenImportingKey_ThenImportsIVCorrectly()
        {
            var currentUser = WindowsIdentity.GetCurrent()
                                             .Name;

            var target = RSAEncryption.LoadSecureContainer("target", currentUser);
            RSAEncryption.LoadSecureContainer("signatureContainer", currentUser);
            var targetPublicKey = target.ExportKeyToXML(false);

            HybridEncryption hybridEncryption = HybridEncryption.CreateEncryption(targetPublicKey, "signatureContainer");

            RandomNumberGenerator random = new RNGCryptoServiceProvider();

            var data = File.ReadAllBytes("appsettings.json");
            var sessionKey = new byte[32];
            var iv = new byte[16];

            random.GetBytes(sessionKey);
            random.GetBytes(iv);

            (SessionKeyContainer key, byte[] encryptedData) encryptedResult = hybridEncryption.EncryptData(sessionKey, data, iv);

            var key = encryptedResult.key;

            var keyBlob = key.ExportToBlob();

            var keyFromBlob = SessionKeyContainer.FromBlob(keyBlob);

            Assert.That(keyFromBlob.IV, Is.EqualTo(key.IV));
        }

        [Test]
        public void GivenEncryptionKeyBlob_WhenImportingKey_ThenImportsHMACHashCorrectly()
        {
            var currentUser = WindowsIdentity.GetCurrent()
                                             .Name;

            var target = RSAEncryption.LoadSecureContainer("target", currentUser);
            RSAEncryption.LoadSecureContainer("signatureContainer", currentUser);
            var targetPublicKey = target.ExportKeyToXML(false);

            HybridEncryption hybridEncryption = HybridEncryption.CreateEncryption(targetPublicKey, "signatureContainer");

            RandomNumberGenerator random = new RNGCryptoServiceProvider();

            var data =File.ReadAllBytes("appsettings.json");
            var sessionKey = new byte[32];
            var iv = new byte[16];

            random.GetBytes(sessionKey);
            random.GetBytes(iv);

            (SessionKeyContainer key, byte[] encryptedData) encryptedResult = hybridEncryption.EncryptData(sessionKey, data, iv);

            var key = encryptedResult.key;

            var keyBlob = key.ExportToBlob();

            var keyFromBlob = SessionKeyContainer.FromBlob(keyBlob);

            Assert.That(keyFromBlob.HMACHash, Is.EqualTo(key.HMACHash));
        }

        [Test]
        public void GivenEncryptionKeyBlob_WhenImportingKey_ThenImportsSessionKeyCorrectly()
        {
            var currentUser = WindowsIdentity.GetCurrent()
                                             .Name;

            var target = RSAEncryption.LoadSecureContainer("target", currentUser);
            RSAEncryption.LoadSecureContainer("signatureContainer", currentUser);
            var targetPublicKey = target.ExportKeyToXML(false);

            HybridEncryption hybridEncryption = HybridEncryption.CreateEncryption(targetPublicKey, "signatureContainer");

            RandomNumberGenerator random = new RNGCryptoServiceProvider();

            var data = File.ReadAllBytes("appsettings.json");
            var sessionKey = new byte[32];
            var iv = new byte[16];

            random.GetBytes(sessionKey);
            random.GetBytes(iv);

            (SessionKeyContainer key, byte[] encryptedData) encryptedResult = hybridEncryption.EncryptData(sessionKey, data, iv);

            var key = encryptedResult.key;

            var keyBlob = key.ExportToBlob();

            var keyFromBlob = SessionKeyContainer.FromBlob(keyBlob);

            Assert.That(keyFromBlob.SessionKey, Is.EqualTo(key.SessionKey));
        }

        [Test]
        public void GivenEncryptionKeyBlob_WhenImportingKey_ThenDecryptsSessionKeyCorrectly()
        {
            var currentUser = WindowsIdentity.GetCurrent()
                                             .Name;

            var target = RSAEncryption.LoadSecureContainer("target", currentUser);
            RSAEncryption.LoadSecureContainer("signatureContainer", currentUser);

            var targetPublicKey = target.ExportKeyToXML(false);

            HybridEncryption hybridEncryption = HybridEncryption.CreateEncryption(targetPublicKey, "signatureContainer");

            RandomNumberGenerator random = new RNGCryptoServiceProvider();

            var data = File.ReadAllBytes("appsettings.json");
            var sessionKey = new byte[32];
            var iv = new byte[16];

            random.GetBytes(sessionKey);
            random.GetBytes(iv);

            (SessionKeyContainer key, byte[] encryptedData) encryptedResult = hybridEncryption.EncryptData(sessionKey, data, iv);

            var key = encryptedResult.key;

            var keyBlob = key.ExportToBlob();

            var keyFromBlob = SessionKeyContainer.FromBlob(keyBlob);
            var rsaEcryption = RSAEncryption.LoadContainer("target");

            var decryptedSessionKey = rsaEcryption.DecryptData(keyFromBlob.SessionKey);

            Assert.That(sessionKey, Is.EqualTo(decryptedSessionKey));
        }
    }
}