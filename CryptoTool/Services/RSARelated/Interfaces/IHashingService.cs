using System.Security.Authentication;
using static Encryptie_H4.Services.HashingService;

namespace Encryptie_H4.Services.RSARelated.Interfaces
{
    public interface IHashingService
    {
        public string ComputeHash(string input, HashAlgorithmType type);
        public bool VerifyHash(string input, string expectedHash, HashAlgorithmType type);
        public string ComputeFileHash(Stream fileStream, HashAlgorithmType type);
        public bool VerifyHashFile(Stream input, string expectedHash, HashAlgorithmType type);
        public string HmacCreate(string key, string message, HmacType type);
        public bool VerifyHmac(string message, string expectedHash, string key, HmacType type);
        public string HmacCreateKey();
    }
}
