# Encryption.Hybrid
[![Build status](https://ci.appveyor.com/api/projects/status/w70f5i9p0j38t3vj/branch/master?svg=true)](https://ci.appveyor.com/project/jordan-Anderson/encryption-hybrid/branch/master)

Uses combination of Symmetric and Asymmetirc encryption AKA Hybrid encryption

# Architecture
- .NET Framework 4.7 runtime
- Windows XP and above
- NTFS partition 

>.NET Framework 4.7 runtime is only needed during the encryption phase

>The windows os constraint is due to how windows protects keys RSA keys, see [Link](https://msdn.microsoft.com/library/9a179f38-8fb7-4442-964c-fb7b9f39f5b9) for details. 

>The application makes use of NTFS ACL to control access to sensitive files used to store decryption keys as per recommendation from Microsoft. See [Link](https://msdn.microsoft.com/en-gb/library/windows/desktop/aa374872(v=vs.85).aspx) for details.

# License

https://opensource.org/licenses/GPL-3.0