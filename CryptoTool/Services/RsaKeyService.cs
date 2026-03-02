using System.Security.Cryptography;

namespace CryptoTool.Services
{
    public class RsaKeyService
    {
       
        public (string PublicKey, string PrivateKey) GenerateKeyPair(int keySize)
        {
            using (RSA rsa = RSA.Create(keySize))
            {
                
                string publicKey = rsa.ExportRSAPublicKeyPem();

                // Exporteer de privésleutel in PEM-formaat.
                // WAARSCHUWING: Deel deze sleutel nooit! Het moet geheim blijven.
                string privateKey = rsa.ExportRSAPrivateKeyPem();

                return (publicKey, privateKey);
            }
        }
    }
}