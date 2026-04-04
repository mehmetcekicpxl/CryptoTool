using Encryptie_H4.Models.RsaEncryption;
using Encryptie_H4.Services.RSARelated.Interfaces;
using System.Security.Cryptography;
using System.Text;

namespace Encryptie_H4.Services.RSARelated
{


    public class RsaEncryptionService : IEncryptionService
    {
        private KeyCollection currentKeys = new();
        private RSA currentRsa;
        private byte[] signature;
        private RSAParameters sharedParams;

        private string Error;

        public RsaEncryptionResult EncryptKey(string data, string publicKey)
        {

            RsaEncryptionResult result = new RsaEncryptionResult();

            using (RSA rsa = RSA.Create())
            {
                try
                {
                    rsa.ImportFromPem(publicKey);
                    byte[] messageBytes = Encoding.UTF8.GetBytes(data);
                    byte[] encryptedBytes = rsa.Encrypt(messageBytes, RSAEncryptionPadding.OaepSHA256);

                    result.IsSuccesfull = true;
                    result.EncryptiondResult = Convert.ToBase64String(encryptedBytes);

                    return result;
                }

                catch (Exception e)
                {
                    if(e.HResult == -2147024809)
                    {
                        result.AddError("Key is niet geldig, zorg ervoor dat het in PEM formaat is");
                    }
                    
                    else if(e.HResult == -1056964595)
                    {
                        result.AddError("Bericht te lang of PEM key niet geldig");
                    }

                    else
                    {
                        result.AddError("Onbekende error, bericht is mss te lang of PEM key niet geldig");
                    }

                    result.IsSuccesfull = false;
                    result.EncryptiondResult = result.IsSuccesfull ? result.EncryptiondResult : "Error(s): see below"; 
               
                    return result;
                }

            }
        }

        public RsaEncryptionResult DecryptKey(string encrypteData, string privateKey)
        {
            RsaEncryptionResult result = new RsaEncryptionResult();

            using (RSA rsa = RSA.Create())
            {
                try
                {
                    rsa.ImportFromPem(privateKey);
                    byte[] decryptedBytes = rsa.Decrypt(Convert.FromBase64String(encrypteData), RSAEncryptionPadding.OaepSHA256);

                    result.IsSuccesfull = true;
                    result.EncryptiondResult = Encoding.UTF8.GetString(decryptedBytes);

                    return result;
                }

                catch (Exception e)
                {
                    result.IsSuccesfull = false;
                    result.AddError("Verkeede combinatie");
                    return result;
                }

            }
        }

        public RsaEncryptionResult SignData(string data, string privateKey)
        {
            RsaEncryptionResult result = new RsaEncryptionResult();

            using (RSA rsa = RSA.Create())
            {
                try
                {
                    rsa.ImportFromPem(privateKey);

                    byte[] dataToSign = Encoding.UTF8.GetBytes(data);

                    byte[] hash;
                    using (SHA256 sha256 = SHA256.Create())
                    {
                        hash = sha256.ComputeHash(dataToSign);
                    }

                    RSAPKCS1SignatureFormatter formatter = new RSAPKCS1SignatureFormatter(rsa);
                    formatter.SetHashAlgorithm("SHA256");

                    byte[] signature = formatter.CreateSignature(hash);

                    result.IsSuccesfull = true;
                    result.EncryptiondResult = Convert.ToBase64String(signature);

                    return result;
                }

                catch (Exception e)
                {

                    result.AddError("fout bij signing, kijk of de key geldig is en in PEM formaat is");
                    result.IsSuccesfull = false;

                    return result;
                }
           

            }

        }

        public RsaEncryptionResult VerifySignature(string data, string signature, string publicKey)
        {
            RsaEncryptionResult result = new RsaEncryptionResult();

            using (RSA rsa = RSA.Create())
            {
                try
                {
                    rsa.ImportFromPem(publicKey);

                    byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                    byte[] hash;

                    using (SHA256 sha256 = SHA256.Create())
                    {
                        hash = sha256.ComputeHash(dataBytes);
                    }

                    RSAPKCS1SignatureDeformatter deformatter = new RSAPKCS1SignatureDeformatter(rsa);
                    deformatter.SetHashAlgorithm("SHA256");

                    byte[] signatureBytes = Convert.FromBase64String(signature);

                    result.IsSuccesfull = deformatter.VerifySignature(hash, signatureBytes);

                    return result;
                }

                catch (Exception e)
                {

                    result.AddError("fout bij verifying");
                    result.IsSuccesfull = false;

                    return result;
                }
              
            }
        }

        public KeyCollection GenerateKeys()
        {
            using (RSA rsa = RSA.Create(2048))
            {
                currentKeys.RsaPublicKey = rsa.ExportRSAPublicKeyPem();
                currentKeys.RsaPrivateKey = rsa.ExportRSAPrivateKeyPem();
                currentRsa = rsa;
            }

            using (Aes aes = Aes.Create())
            {
                aes.GenerateKey();
                currentKeys.AesKey = Convert.ToBase64String(aes.Key);
            }

            return currentKeys;
        }

        public KeyCollection GetKeys()
        {
            return currentKeys;
        }

        public RsaEncryptionResult SignFile(Stream fileStream, string privateKeyPem)
        {
            var result = new RsaEncryptionResult();
            try
            {
                using RSA rsa = RSA.Create();
                rsa.ImportFromPem(privateKeyPem);

                // Reads the file stream, hashes it using SHA256, and signs the hash with the private key
                byte[] signatureBytes = rsa.SignData(fileStream, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                result.IsSuccesfull = true;
                result.EncryptiondResult = Convert.ToBase64String(signatureBytes);
            }
            catch (Exception ex)
            {
                result.IsSuccesfull = false;
                // In a real app we log ex.Message, but we return a safe error to the result object
                result.AddError("Kan het bestand niet ondertekenen. Controleer of de private key geldig is.");
            }
            return result;
        }

        public RsaEncryptionResult VerifyFileSignature(Stream fileStream, string signatureBase64, string publicKeyPem)
        {
            var result = new RsaEncryptionResult();
            try
            {
                using RSA rsa = RSA.Create();
                rsa.ImportFromPem(publicKeyPem);

                byte[] signatureBytes = Convert.FromBase64String(signatureBase64);

                // Hashes the file stream again and verifies if it matches the decrypted signature
                bool isValid = rsa.VerifyData(fileStream, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                result.IsSuccesfull = isValid;
            }
            catch (Exception)
            {
                result.IsSuccesfull = false;
                result.AddError("Kan de handtekening niet verifiëren. Controleer de public key en de handtekening.");
            }
            return result;
        }
    }
}
