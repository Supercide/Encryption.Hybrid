using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Principal;
using Encryption.Hybrid.Asymmetric;
using Encryption.Hybrid.Constants;
using Encryption.Hybrid.Hybrid;
using NUnit.Framework;

namespace Encryption.HybridTests.Encryption.HybridEncryptTests
{
    public class WhenEncryptingData
    {
        private readonly HybridEncryption _hybridEncryption;
        private readonly IEnumerable<string> _files;

        public WhenEncryptingData()
        {
            _files = Directory.EnumerateFiles(WellKnownPaths.RSA_MACHINEKEYS)
                              .ToArray();

            var currentUser = WindowsIdentity.GetCurrent()
                                             .Name;

            var signatureContainer ="signature";
            var encryptionContainer = "encryption";

            var encryptionKey = RSAEncryption.CreateSecureContainer(encryptionContainer, currentUser);
            
            var encryptionPublicKey = encryptionKey.ExportKey(false);

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

        [TearDown]
        public void CleanUp()
        {
            var files = Directory.EnumerateFiles(WellKnownPaths.RSA_MACHINEKEYS);

            var newFiles = files.Except(_files);

            foreach (var newFile in newFiles)
            {
                File.Delete(newFile);
            }
        }
    }
}
