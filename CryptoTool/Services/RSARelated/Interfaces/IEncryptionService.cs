using Encryptie_H4.Models.RsaEncryption;

namespace Encryptie_H4.Services.RSARelated.Interfaces
{
    public interface IEncryptionService
    {
        public RsaEncryptionResult SignData(string data, string privateKey);
        public RsaEncryptionResult VerifySignature(string data, string signature, string publicKey);
        public RsaEncryptionResult EncryptKey(string data, string publicKey);
        public RsaEncryptionResult DecryptKey(string encrypteData, string privateKey);
        public KeyCollection GenerateKeys();
        public KeyCollection GetKeys();
        public RsaEncryptionResult SignFile(Stream stream, string privateKeyPem);
        public RsaEncryptionResult VerifyFileSignature(Stream fileStream, string signature, string publicKey);
    }
}
