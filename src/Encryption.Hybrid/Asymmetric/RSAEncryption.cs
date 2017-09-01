using System;
using System.IO;
using System.Security.Cryptography;
using Encryption.Hybrid.Hybrid;

namespace Encryption.Hybrid.Asymmetric {
    /// <summary>
    /// RSA implementation of the <see cref="IAsymmetricKeyEncryption"/> interface
    /// </summary>
    public class RSAEncryption : IAsymmetricKeyEncryption, IDigitalSignature
    {
        private readonly string _containerName;
        private readonly CspParameters _cspParams;

        public void AddKey(int keySize, bool exportable)
        {
            RSACryptoServiceProvider rsa = GetCryptoServiceProvider(exportable, false, _containerName);
            rsa.KeySize = keySize;
            rsa.PersistKeyInCsp = true;
            rsa.Clear();
        }

        public void DeleteKey()
        {
            RSACryptoServiceProvider rsa = GetCryptoServiceProvider(false, true, _containerName);
            rsa.PersistKeyInCsp = false;
            rsa.Clear();
        }

        public void ImportKey(string key, bool exportable)
        {
            RSACryptoServiceProvider rsa = GetCryptoServiceProvider(exportable, false, _containerName);
            rsa.FromXmlString(key);
            rsa.PersistKeyInCsp = true;
            rsa.Clear();
        }

        public void ExportKey(string xmlFileName, bool includePrivateParameters)
        {
            RSACryptoServiceProvider rsa = GetCryptoServiceProvider(false, false, _containerName);
            string xmlString = rsa.ToXmlString(includePrivateParameters);
            File.WriteAllText(xmlFileName, xmlString);
            rsa.Clear();
        }

        private RSACryptoServiceProvider GetCryptoServiceProvider(bool exportable, bool keyMustExist, string containerName)
        {
            var csp = GetCspParameters(exportable, keyMustExist, containerName);

            return new RSACryptoServiceProvider(csp);
        }

        private CspParameters GetCspParameters(bool exportable, bool keyMustExist, string containerName)
        {
            CspParameters csp = new CspParameters
            {
                KeyContainerName = containerName,
                KeyNumber = (int) KeyNumber.Exchange,
            };

            csp.Flags |= CspProviderFlags.UseMachineKeyStore | CspProviderFlags.NoPrompt;

            if(!exportable && !keyMustExist)
                csp.Flags |= CspProviderFlags.UseNonExportableKey;

            if(keyMustExist)
                csp.Flags |= CspProviderFlags.UseExistingKey;

            return csp;
        }

        /// <summary>
        /// Initializes class from existing <paramref name="containerName"/>
        /// </summary>
        /// <param name="containerName"></param>
        public RSAEncryption(string containerName)
        {
            _containerName = containerName;
        }

        /// <summary>
        /// Creates or loads an <paramref name="containerName"/> applying NTFS access rules for the provided user identity
        /// </summary>
        /// <param name="containerName"></param>
        /// <param name="username">NT Identity of users containerName is restricted too</param>
        /// <returns><see cref="RSAEncryption"/></returns>
        public RSAEncryption(string containerName, string username)
        {
            _containerName = containerName; 

            RSAContainerFactory.Create(_containerName, username)
                               .Dispose();
        }

        /// <summary>
        /// Exports key to xml format
        /// </summary>
        /// <param name="includePrivate">Specifies if it should include private data in the key</param>
        /// <returns>key in xml format</returns>
        public string ExportKeyToXML(bool includePrivate)
        {
            using (RSACryptoServiceProvider rsaCryptoServiceProvider = GetCryptoServiceProvider(true, true, _containerName))
            {
                return rsaCryptoServiceProvider.ToXmlString(includePrivate);
            }
        }

        /// <summary>
        /// Encrypts <paramref name="data"/>data using the current public key
        /// </summary>
        /// <param name="data">byte array of data to encrypt</param>
        /// <returns>returns encrypted data in bytes</returns>
        public byte[] EncryptData(byte[] data)
        {
            using (RSACryptoServiceProvider rsa = GetCryptoServiceProvider(false, true, _containerName))
            {
                return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            }
        }

        /// <summary>
        /// Decrypts data using the current private key
        /// </summary>
        /// <param name="data">byte array of data to decrypt</param>
        /// <returns>unencrypted data in bytes</returns>
        public byte[] DecryptData(byte[] data)
        {
            using (RSACryptoServiceProvider rsa = GetCryptoServiceProvider(false, true, _containerName))
            {
                return rsa.DecryptValue(data);
            }
        }

        /// <summary>
        /// Signs data using the private key
        /// </summary>
        /// <param name="data"></param>
        /// <returns>signature of data</returns>
        public byte[] SignData(byte[] data)
        {
            using (RSACryptoServiceProvider rsaCryptoServiceProvider = GetCryptoServiceProvider(false, false, _containerName))
            {
                return rsaCryptoServiceProvider.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        /// <summary>
        /// Verifies the signature using the current public key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <returns>true if the signature id valid, false if it fails verification</returns>
        public bool VerifyData(byte[] data, byte[] signature)
        {
            using (RSACryptoServiceProvider rsaCryptoServiceProvider = GetCryptoServiceProvider(false, false, _containerName))
            {
                return rsaCryptoServiceProvider.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        public static RSAEncryption CreateWithKey(string key)
        {
            var rsa = new RSAEncryption($"{Guid.NewGuid()}");

            rsa.ImportKey(key, true);

            return rsa;
        }

        public static RSAEncryption LoadContainer(string containerName)
        {
            return new RSAEncryption(containerName);
        }

        public static RSAEncryption CreateSecureContainer(string containerName, string windowsIdentity)
        {
            return new RSAEncryption(containerName, windowsIdentity);
        }

        public static RSAEncryption CreateContainer(string someContainer)
        {
            throw new NotImplementedException();
        }
    }
}