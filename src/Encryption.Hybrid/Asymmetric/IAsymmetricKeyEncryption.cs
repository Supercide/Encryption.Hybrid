namespace Encryption.Hybrid.Asymmetric {
    /// <summary>
    /// Encrypts data via Asymmetric algorithm 
    /// </summary>
    public interface IAsymmetricKeyEncryption
    {
        /// <summary>
        /// Exports key to xml format
        /// </summary>
        /// <param name="includePrivate">Specifies if it should include private data in the key</param>
        /// <returns>key in xml format</returns>
        string ExportKey(bool includePrivate);
        /// <summary>
        /// Encrypts data using the current public key
        /// </summary>
        /// <param name="data">byte array of data to encrypt</param>
        /// <returns>returns encrypted data in bytes</returns>
        byte[] EncryptData(byte[] data);
        /// <summary>
        /// Decrypts data using the current private key
        /// </summary>
        /// <param name="data">byte array of data to decrypt</param>
        /// <returns>unencrypted data in bytes</returns>
        byte[] DecryptData(byte[] data);
    }
}