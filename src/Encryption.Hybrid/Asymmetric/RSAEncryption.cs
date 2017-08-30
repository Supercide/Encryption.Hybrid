using System.Security.Cryptography;
using Encryption.Hybrid.Hybrid;

namespace Encryption.Hybrid.Asymmetric {
    /// <summary>
    /// RSA implementation of the <see cref="IAsymmetricKeyEncryption"/> interface
    /// </summary>
    public class RSAEncryption : IAsymmetricKeyEncryption, IDigitalSignature
    {
        private readonly RSAContainer _container;
        private readonly string _username;
        private string _publicKey;
        

        public RSAEncryption() { }

        /// <summary>
        /// Initializes class from existing container
        /// </summary>
        /// <param name="container"></param>
        protected RSAEncryption(RSAContainer container)
        {
            _container = container;
        }

        /// <summary>
        /// Creates or loads an container applying NTFS access rules for the provided user identity
        /// </summary>
        /// <param name="container"></param>
        /// <param name="username">NT Identity of users container is restricted too</param>
        /// <returns><see cref="RSAEncryption"/></returns>
        protected RSAEncryption(RSAContainer container, string username)
        {
            _container = container;
            _username = username;

            RSAContainerFactory.Create(container.Name, username)
                               .Dispose();
        }

        /// <summary>
        /// Creates or loads an container applying NTFS access rules for the provided user identity
        /// </summary>
        /// <param name="container"></param>
        /// <param name="username">NT Identity of users container is restricted too</param>
        /// <returns><see cref="RSAEncryption"/></returns>
        public static RSAEncryption LoadSecureContainer(RSAContainer container, string username)
        {
            // throw exception if container already exists
            return new RSAEncryption(container, username);
        }

        /// <summary>
        /// Initializes class from existing container or creates a new container if none exists
        /// </summary>
        /// <param name="container">Name container</param>
        /// <returns><see cref="RSAEncryption"/></returns>
        public static RSAEncryption LoadContainer(RSAContainer container)
        {
            return new RSAEncryption(container);
        }

        /// <summary>
        /// initializes class with supplied public key 
        /// </summary>
        /// <param name="publicKey">public key in xml format</param>
        /// <returns><see cref="RSAEncryption"/></returns>
        public static RSAEncryption FromPublicKey(string publicKey)
        {
            return new RSAEncryption
            {
                _publicKey = publicKey
            };
        }

        /// <summary>
        /// Exports key to xml format
        /// </summary>
        /// <param name="includePrivate">Specifies if it should include private data in the key</param>
        /// <returns>key in xml format</returns>
        public string ExportKeyToXML(bool includePrivate)
        {
            using (RSACryptoServiceProvider rsaCryptoServiceProvider = RSAContainerFactory.CreateFromContainer(_container.Name))
            {
                return rsaCryptoServiceProvider.ToXmlString(includePrivate);
            }
        }

        /// <summary>
        /// Encrypts data using the current public key
        /// </summary>
        /// <param name="data">byte array of data to encrypt</param>
        /// <returns>returns encrypted data in bytes</returns>
        public byte[] EncryptData(byte[] data)
        {
            if(_publicKey == null)
            {
                using (RSACryptoServiceProvider rsaCryptoServiceProvider = RSAContainerFactory.Create(_container.Name, _username))
                {
                    return rsaCryptoServiceProvider.Encrypt(data, RSAEncryptionPadding.Pkcs1);
                }
            }

            using (RSACryptoServiceProvider rsaCryptoServiceProvider = RSAContainerFactory.CreateFromPublicKey(_publicKey))
            {
                return rsaCryptoServiceProvider.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            }
        }
        /// <summary>
        /// Decrypts data using the current private key
        /// </summary>
        /// <param name="data">byte array of data to decrypt</param>
        /// <returns>unencrypted data in bytes</returns>
        public byte[] DecryptData(byte[] data)
        {
            using (RSACryptoServiceProvider rsaCryptoServiceProvider = RSAContainerFactory.CreateFromContainer(_container.Name))
            {
                return rsaCryptoServiceProvider.Decrypt(data, RSAEncryptionPadding.Pkcs1);
            }
        }
        /// <summary>
        /// Signs data using the private key
        /// </summary>
        /// <param name="data"></param>
        /// <returns>signature of data</returns>
        public byte[] SignData(byte[] data)
        {
            using (RSACryptoServiceProvider rsaCryptoServiceProvider = RSAContainerFactory.CreateFromContainer(_container.Name))
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
            using (RSACryptoServiceProvider rsaCryptoServiceProvider = RSAContainerFactory.CreateFromPublicKey(_publicKey))
            {
                return rsaCryptoServiceProvider.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }
    }
}