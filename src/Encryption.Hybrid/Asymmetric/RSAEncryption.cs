using System.Security.Cryptography;

namespace Encryption.Hybrid.Asymmetric {
    /// <summary>
    /// RSA implementation of the <see cref="IAsymmetricKeyEncryption"/> interface
    /// </summary>
    public class RSAEncryption : IAsymmetricKeyEncryption, IDigitalSignature
    {
        private readonly string _containerName;
        private readonly string _username;
        private string _publicKey;
        

        public RSAEncryption() { }

        /// <summary>
        /// Initializes class from existing container
        /// </summary>
        /// <param name="containerName"></param>
        protected RSAEncryption(string containerName)
        {
            _containerName = containerName;
        }

        /// <summary>
        /// Creates or loads an container applying NTFS access rules for the provided user identity
        /// </summary>
        /// <param name="containerName"></param>
        /// <param name="username">NT Identity of users container is restricted too</param>
        /// <returns><see cref="RSAEncryption"/></returns>
        protected RSAEncryption(string containerName, string username)
        {
            _containerName = containerName;
            _username = username;

            RSAContainerFactory.Create(containerName, username)
                               .Dispose();
        }

        /// <summary>
        /// Creates or loads an container applying NTFS access rules for the provided user identity
        /// </summary>
        /// <param name="containerName"></param>
        /// <param name="username">NT Identity of users container is restricted too</param>
        /// <returns><see cref="RSAEncryption"/></returns>
        public static RSAEncryption LoadSecureContainer(string containerName, string username)
        {
            // throw exception if container already exists
            return new RSAEncryption(containerName, username);
        }

        /// <summary>
        /// Initializes class from existing container or creates a new container if none exists
        /// </summary>
        /// <param name="containerName">Name container</param>
        /// <returns><see cref="RSAEncryption"/></returns>
        public static RSAEncryption LoadContainer(string containerName)
        {
            return new RSAEncryption(containerName);
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
            using (RSACryptoServiceProvider rsaCryptoServiceProvider = RSAContainerFactory.CreateFromContainer(_containerName))
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
                using (RSACryptoServiceProvider rsaCryptoServiceProvider = RSAContainerFactory.Create(_containerName, _username))
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
            using (RSACryptoServiceProvider rsaCryptoServiceProvider = RSAContainerFactory.CreateFromContainer(_containerName))
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
            using (RSACryptoServiceProvider rsaCryptoServiceProvider = RSAContainerFactory.CreateFromContainer(_containerName))
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