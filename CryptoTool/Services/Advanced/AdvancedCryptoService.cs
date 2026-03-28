using CryptoTool.Services.Advanced.Interfaces;
using System.Security.Cryptography;

namespace CryptoTool.Services.Advanced
{
    public class AdvancedCryptoService : IAdvancedCryptoService
    {
        public string GenerateSecurePassword(int length, bool useNumbers, bool useSymbols)
        {
            const string lower = "abcdefghijklmnopqrstuvwxyz";
            const string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string numbers = "0123456789";
            const string symbols = "!@#$%^&*()_-+=<>?";

            string characterSet = lower + upper;
            if (useNumbers) characterSet += numbers;
            if (useSymbols) characterSet += symbols;

            char[] password = new char[length];
            byte[] randomBytes = new byte[length];

            // Generates cryptographically strong random bytes
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }

            for (int i = 0; i < length; i++)
            {
                int index = randomBytes[i] % characterSet.Length;
                password[i] = characterSet[index];
            }

            return new string(password);
        }

        public string DeriveKeyPbkdf2(string password, string saltBase64, int iterations)
        {
            byte[] salt = Convert.FromBase64String(saltBase64);

            // Derives a 256-bit key from a password using PBKDF2
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
            {
                byte[] keyBytes = pbkdf2.GetBytes(32);
                return Convert.ToBase64String(keyBytes);
            }
        }
        public (string EncryptedMessage, string EncryptedSessionKey, string Iv) EncryptHybrid(string plainText, string rsaPublicKeyPem)
        {
            // 1. Generate a random, one-time AES session key and IV
            using Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.GenerateKey();
            aes.GenerateIV();

            // 2. Encrypt the large plain text message using the fast AES algorithm
            byte[] encryptedData;
            using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                using (StreamWriter sw = new StreamWriter(cs))
                {
                    sw.Write(plainText);
                }
                encryptedData = ms.ToArray();
            }

            // 3. Encrypt the small AES session key using the receiver's RSA Public Key
            byte[] encryptedSessionKey;
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportFromPem(rsaPublicKeyPem); // Loads the PEM format public key
                encryptedSessionKey = rsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);
            }

            // Return all necessary components as Base64 strings so they can be sent safely
            return (
                Convert.ToBase64String(encryptedData),
                Convert.ToBase64String(encryptedSessionKey),
                Convert.ToBase64String(aes.IV)
            );
        }
    }
}
