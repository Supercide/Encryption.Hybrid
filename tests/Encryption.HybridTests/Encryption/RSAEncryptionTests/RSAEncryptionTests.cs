using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Encryption.Hybrid.Asymmetric;
using Encryption.Hybrid.Constants;
using NUnit.Framework;

namespace Encryption.HybridTests.Encryption.RSAEncryptionTests
{

    [TestFixture]
    public class RSAEncryptionTests
    {
        private readonly IEnumerable<string> _files;

        readonly string User;

        public RSAEncryptionTests()
        {
            User = WindowsIdentity.GetCurrent().Name;

            _files = Directory.EnumerateFiles(WellKnownPaths.RSA_MACHINEKEYS)
                              .ToArray();
        }

        [Test]
        public void GivenContainerAlreadyExistsForAnotherUser_WhenCreatingContainerWithSameName_ThenThrowsCryptographicException()
        {
            RSAEncryption.CreateSecureContainer("Container", "SYSTEM");

            Assert.Throws<CryptographicException>(() => RSAEncryption.CreateContainer("Container"));
        }

        [Test]
        public void GivenContainerAlreadyExistsForAnotherUser_WhenLoadingContainerWithSameName_ThenThrowsCryptographicException()
        {
            RSAEncryption.CreateSecureContainer("Container", "SYSTEM");

            Assert.Throws<CryptographicException>(() => RSAEncryption.LoadContainer("Container"));
        }

        [Test]
        public void GivenContainerAlreadyExistsForCurrentUser_WhenLoadingContainerWithSameName_ThenLoadsContainer()
        {
            RSAEncryption.CreateSecureContainer("Container", User);

            Assert.DoesNotThrow(() => RSAEncryption.LoadContainer("Container"));
        }

        [Test]
        public void GivenContainerAlreadyExistsForCurrentUser_WhenCreatingContainerWithSameName_ThenLoadsContainer()
        {
            RSAEncryption.CreateSecureContainer("Container", User);

            Assert.DoesNotThrow(() => RSAEncryption.CreateContainer("Container"));
        }

        [Test]
        public void GivenContainerAlreadyExists_WhenCreatingContainerWithSameName_ThenLoadsContainer()
        {
            RSAEncryption.CreateContainer("Container");

            Assert.DoesNotThrow(() => RSAEncryption.CreateContainer("Container"));
        }

        [Test]
        public void GivenContainerAlreadyExists_WhenLoadingContainerWithSameName_ThenLoadsContainer()
        {
            RSAEncryption.CreateContainer("Container");

            Assert.DoesNotThrow(() => RSAEncryption.LoadContainer("Container"));
        }

        [Test]
        public void GivenValidData_WhenExportingKey_ThenReturnsExportedKeyToXML()
        {
            RSAEncryption encryption = RSAEncryption.CreateContainer("SomeContainer");

            var rsaExport = encryption.ExportKey(false);

            Assert.That(rsaExport, Is.Not.Null);
        }

        [Test]
        public void GivenImportedKey_WhenEncryptingData_ThenEncryptsData_WithImportedKey()
        {
            var expectedMessage = "hello world";
            var expectedMessageBytes = Encoding.UTF8.GetBytes(expectedMessage);

            RSAEncryption originalRSAEncryption = RSAEncryption.CreateContainer("SomeContainer");

            var exportedPublicKey = originalRSAEncryption.ExportKey(false);

            var rsaEncryptionWithImportedKey = RSAEncryption.CreateWithKey(exportedPublicKey);

            var encryptedMessageBytes = rsaEncryptionWithImportedKey.EncryptData(expectedMessageBytes);

            var actualMessage = Encoding.UTF8.GetString(originalRSAEncryption.DecryptData(encryptedMessageBytes));

            Assert.That(actualMessage, Is.EqualTo(expectedMessage));
        }

        [Test]
        public void GivenEncryptedData_WhenDecryptingData_ThenDecryptsData()
        {
            var expectedMessage = "hello world";
            var expectedMessageBytes = Encoding.UTF8.GetBytes(expectedMessage);

            RSAEncryption rsaEncryption = RSAEncryption.CreateContainer("SomeContainer");

            var encryptedMessageBytes = rsaEncryption.EncryptData(expectedMessageBytes);

            var actualMessage = Encoding.UTF8.GetString(rsaEncryption.DecryptData(encryptedMessageBytes));

            Assert.That(actualMessage, Is.EqualTo(expectedMessage));
        }

        [Test]
        public void GivenUsername_WhenCreatingContainer_ThenOnlyProvidedUserNameHasAccess()
        {
            var container =$"{Guid.NewGuid()}";

            var rsaEncryption = RSAEncryption.CreateSecureContainer(container, User);

            rsaEncryption.ExportKey(false);

            var cspContainer = LoadCspKeyContainerInfo(container);

            var rule = cspContainer.CryptoKeySecurity.GetAccessRules(true, true, typeof(NTAccount))
                                .Cast<AuthorizationRule>()
                                .SingleOrDefault();

            Assert.That(rule, Is.Not.Null);

            Assert.That(rule.IdentityReference.Value, Is.EqualTo(User));
        }

        [Test]
        public void GivenUsername_WhenCreatingContainer_ThenSetsAccessControlToReadOnlyForUser()
        {
            var container =$"{Guid.NewGuid()}";

            var rsaEncryption = RSAEncryption.CreateSecureContainer(container, User);

            var rsaCryptoServiceProvider = new RSACryptoServiceProvider(new CspParameters()
            {
                KeyContainerName = container
            });

            rsaEncryption.ExportKey(false);

            var path = Path.Combine(WellKnownPaths.RSA_MACHINEKEYS, rsaCryptoServiceProvider.CspKeyContainerInfo.UniqueKeyContainerName);

                FileSecurity fSecurity = new FileSecurity(path, AccessControlSections.Access);

                var accessRule = fSecurity.GetAccessRules(true, true, typeof(NTAccount))
                                          .Cast<FileSystemAccessRule>()
                                          .SingleOrDefault();

                var rights = accessRule.FileSystemRights
                                       .ToString()
                                       .Split(',')
                                       .Select(x => (FileSystemRights)Enum.Parse(typeof(FileSystemRights), x, true));

                Assert.NotNull(rights);
                Assert.That(rights.Count(), Is.EqualTo(1));
                Assert.That(rights.Any(systemRights => systemRights == FileSystemRights.FullControl));
            
        }

        
        private static CspKeyContainerInfo LoadCspKeyContainerInfo(string keyContainerName)
        {
            CspParameters cp = new CspParameters
            {
                KeyContainerName = keyContainerName,
                Flags = CspProviderFlags.UseMachineKeyStore
            };

            CspKeyContainerInfo container = new CspKeyContainerInfo(cp);
            return container;
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
