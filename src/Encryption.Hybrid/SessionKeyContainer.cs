using System;
using System.Collections.Generic;
using System.Linq;

namespace Encryption.Hybrid {
    /// <summary>
    /// 
    /// </summary>
    public class SessionKeyContainer
    {
        private const int SESSION_KEY_INDEX = 0;
        private const int IV_INDEX = 4;
        private const int HMAC_INDEX = 8;
        private const int SIGNATURE_INDEX = 12;
        private const int HEADER_OFFSET = 16;

        public byte[] SessionKey { get; }
        public byte[] IV { get; }
        public byte[] HMACHash { get; }
        public byte[] Signature { get; }

        public SessionKeyContainer(byte[] sessionKey, byte[] iv, byte[] hmacHash, byte[] signature)
        {
            SessionKey = sessionKey;
            IV = iv;
            HMACHash = hmacHash;
            Signature = signature;
        }

        public static SessionKeyContainer FromBlob(byte[] blob)
        {
            var sessionKeyLength = ExtractHeader(SESSION_KEY_INDEX, blob);

            var iVLength = ExtractHeader(IV_INDEX, blob);

            var hmacLength = ExtractHeader(HMAC_INDEX, blob);
            var signatureLength = ExtractHeader(SIGNATURE_INDEX, blob);

            var sessionKey = ExtractData(HEADER_OFFSET + 0, sessionKeyLength, blob);
            var iv = ExtractData(HEADER_OFFSET + sessionKeyLength, iVLength, blob);
            var hmac = ExtractData(HEADER_OFFSET + sessionKeyLength + iVLength, hmacLength, blob);
            var signature = ExtractData(HEADER_OFFSET + sessionKeyLength + iVLength + hmacLength, signatureLength, blob);

            return new SessionKeyContainer(sessionKey, iv, hmac, signature);
        }

        private static byte[] ExtractData(int index, int length, byte[] blob)
        {
            return blob.Skip(index)
                       .Take(length)
                       .ToArray();
        }
        private static int ExtractHeader(int index, byte[] blob)
        {
            var headerBlob = blob.Skip(index)
                                 .Take(4)
                                 .ToArray();

            return BitConverter.ToInt32(headerBlob, 0);
        }

        private byte[] GetBytes(int value)
        {
            var bytes = BitConverter.GetBytes(value);

            return bytes;
        }

        public byte[] ExportToBlob()
        {
            // 16 bytes for the header
            var sessionKeyHeader = GetBytes(SessionKey.Length);
            var ivHeader = GetBytes(IV.Length);
            var hmacHashKeyHeader = GetBytes(HMACHash.Length);
            var signatureHeader = GetBytes(Signature.Length);

            List<byte> blob = new List<byte>();

            blob.AddRange(sessionKeyHeader);
            blob.AddRange(ivHeader);
            blob.AddRange(hmacHashKeyHeader);
            blob.AddRange(signatureHeader);

            blob.AddRange(SessionKey);
            blob.AddRange(IV);
            blob.AddRange(HMACHash);
            blob.AddRange(Signature);

            return blob.ToArray();
        }
    }
}