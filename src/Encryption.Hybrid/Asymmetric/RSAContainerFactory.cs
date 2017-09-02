using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using Encryption.Hybrid.Constants;

namespace Encryption.Hybrid.Asymmetric {
    internal class RSAContainerFactory
    {
        public static RSACryptoServiceProvider Create(string containerName, int keySize = 2048)
        {
            var cspParams = CreateCspParameters(containerName);

            RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(keySize, cspParams)
            {
                PersistKeyInCsp = true
            };

            return rsaProvider;
        }

        public static RSACryptoServiceProvider Create(string containerName, string username, int keySize = 2048)
        {
            var cspParams = CreateCspParameters(containerName);

            RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(keySize, cspParams)
            {
                PersistKeyInCsp = true
            };

            SetFileAccessRule(username, rsaProvider.CspKeyContainerInfo.UniqueKeyContainerName);

            return rsaProvider;
        }

        private static void SetFileAccessRule(string username, string uniqueKeyContainerName)
        {
            var filePath = Path.Combine(WellKnownPaths.RSA_MACHINEKEYS, uniqueKeyContainerName);

            var fs = new FileSecurity(filePath, AccessControlSections.All);

            AuthorizationRuleCollection accessRules = fs.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount));

            fs.SetAccessRuleProtection(true, false); 

            foreach (FileSystemAccessRule accessRule in accessRules) 
            {
                fs.PurgeAccessRules(accessRule.IdentityReference);  
            }

            fs.AddAccessRule(new FileSystemAccessRule(username, FileSystemRights.FullControl, AccessControlType.Allow));

            File.SetAccessControl(filePath, fs);
        }

        private static CspParameters CreateCspParameters(string containerName)
        {
            CspParameters cspParams = new CspParameters
            {
                KeyContainerName = containerName,
                KeyNumber = (int) KeyNumber.Exchange,
                Flags = CspProviderFlags.UseMachineKeyStore | CspProviderFlags.NoPrompt,
            };

            return cspParams;
        }
    }
}