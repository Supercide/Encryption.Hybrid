﻿using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Principal;
using Encryption.Hybrid;
using Encryption.Hybrid.Asymmetric;
using Encryption.Hybrid.Constants;
using Encryption.Hybrid.Hybrid;
using NUnit.Framework;

namespace Encryption.HybridTests.Encryption.HybridEncryptTests
{
    public class WhenDecryptingData
    {
        private readonly HybridEncryption _hybridEncryption;
        private readonly HybridDecryption _hybridDecryption;
        private IEnumerable<string> _files;

        public WhenDecryptingData()
        {
            _files = Directory.EnumerateFiles(WellKnownPaths.RSA_MACHINEKEYS)
                              .ToArray();

            var currentUser = WindowsIdentity.GetCurrent()
                                             .Name;

            var signatureContainer ="signature";
            var encryptionContainer ="encryption";

            var encryptionKey = RSAEncryption.CreateSecureContainer(encryptionContainer, currentUser);
            var signingKey = RSAEncryption.CreateSecureContainer(signatureContainer, currentUser);

            var signaturePublicKey = signingKey.ExportKey(false);
            var encryptionPublicKey = encryptionKey.ExportKey(false);

            _hybridEncryption = HybridEncryption.Create(encryptionPublicKey, signatureContainer);
            _hybridDecryption = HybridDecryption.Create(encryptionContainer, signaturePublicKey);
        }

        [Test]
        public void GivenEncryptingData_WhenDecryptingData_ThenDataIsDecrypted()
        {
            RandomNumberGenerator random = new RNGCryptoServiceProvider();

            var data = new byte[512];
            var sessionKey = new byte[32];
            var iv = new byte[16];

            random.GetBytes(sessionKey);
            random.GetBytes(iv);
            random.GetBytes(data);

            (SessionKeyContainer key, byte[] encryptedData) encryptedResult = _hybridEncryption.EncryptData(sessionKey, data, iv);

            var decryptedData = _hybridDecryption.DecryptData(encryptedResult.key, encryptedResult.encryptedData);

            Assert.That(decryptedData, Is.EqualTo(data));
        }

        [Test]
        public void GivenEncryptingData_WhenDecryptingData_FromImportedKey_ThenDataIsDecrypted()
        {
            RandomNumberGenerator random = new RNGCryptoServiceProvider();

            var data = new byte[512];
            var sessionKey = new byte[32];
            var iv = new byte[16];

            random.GetBytes(sessionKey);
            random.GetBytes(iv);
            random.GetBytes(data);

            (SessionKeyContainer key, byte[] encryptedData) encryptedResult = _hybridEncryption.EncryptData(sessionKey, data, iv);

            var keyBlob = encryptedResult.key.ExportToBlob();

            var keyFromBlob = SessionKeyContainer.FromBlob(keyBlob);

            var decryptedData = _hybridDecryption.DecryptData(keyFromBlob, encryptedResult.encryptedData);

            Assert.That(decryptedData, Is.EqualTo(data));
        }

        [OneTimeTearDown]
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
