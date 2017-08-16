using System.IO;
using System.Security.Cryptography;

namespace Encryption.Hybrid.Symmetric {
    public class AESEncryption : ISymmetricKeyEncryption
    {
        public byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
        {
            byte[] encrypted;

            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                aes.Key = key;
                aes.IV = iv;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(data, 0, data.Length);
                        cryptoStream.FlushFinalBlock();
                        encrypted = memoryStream.ToArray();
                    }
            }

            return encrypted;
        }

        public byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            byte[] decrypted;

            using (var aesCryptoServiceProvider = new AesCryptoServiceProvider())
            {
                aesCryptoServiceProvider.Mode = CipherMode.CBC;
                aesCryptoServiceProvider.Padding = PaddingMode.PKCS7;

                aesCryptoServiceProvider.Key = key;
                aesCryptoServiceProvider.IV = iv;

                ICryptoTransform decryptor = aesCryptoServiceProvider.CreateDecryptor(aesCryptoServiceProvider.Key, 
                                                                                      aesCryptoServiceProvider.IV);

                using (MemoryStream msDecrypt = new MemoryStream())
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
                    {
                        csDecrypt.Write(data, 0, data.Length);
                        csDecrypt.FlushFinalBlock();
                        decrypted = msDecrypt.ToArray();
                    }
            }

            return decrypted;
        }
    }
}