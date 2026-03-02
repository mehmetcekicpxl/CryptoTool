using System.Security.Cryptography;
using System.Text;
using CryptoTool.Models;

namespace CryptoTool.Services
{
    public class AesEncryptionService
    {
       
        public EncryptionResult Encrypt(string plainText, string keyBase64, string ivBase64, CipherMode mode, PaddingMode padding)
        {
            byte[] key = Convert.FromBase64String(keyBase64);
            byte[] iv = Convert.FromBase64String(ivBase64);
            byte[] encrypted;

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                
                if (mode != CipherMode.ECB)
                {
                    aes.IV = iv;
                }

                aes.Mode = mode;
                aes.Padding = padding;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(plainText);
                        }
                        encrypted = ms.ToArray();
                    }
                }
            }

            return new EncryptionResult
            {
                CipherText = Convert.ToBase64String(encrypted),
                IV = ivBase64,
                Mode = mode.ToString()
            };
        }

        // Ontsleutelt de ciphertext terug naar platte tekst.
        public string Decrypt(string cipherText, string keyBase64, string ivBase64, CipherMode mode, PaddingMode padding)
        {
            byte[] key = Convert.FromBase64String(keyBase64);
            byte[] iv = Convert.FromBase64String(ivBase64);
            byte[] buffer = Convert.FromBase64String(cipherText);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                if (mode != CipherMode.ECB)
                {
                    aes.IV = iv;
                }

                aes.Mode = mode;
                aes.Padding = padding;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream(buffer))
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(cs))
                        {
                            return sr.ReadToEnd();
                        }
                    }
                }
            }
        }
        // Versleutelt een bestand (byte array) en retourneert de versleutelde bytes.
        public byte[] EncryptFile(byte[] fileBytes, string keyBase64, string ivBase64, CipherMode mode, PaddingMode padding)
        {
            byte[] key = Convert.FromBase64String(keyBase64);
            byte[] iv = Convert.FromBase64String(ivBase64);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                if (mode != CipherMode.ECB) aes.IV = iv;
                aes.Mode = mode;
                aes.Padding = padding;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(fileBytes, 0, fileBytes.Length);
                        cs.FlushFinalBlock();
                    }
                    return ms.ToArray();
                }
            }
        }

        // Ontsleutelt een bestand (byte array) en retourneert de originele bytes.
        public byte[] DecryptFile(byte[] fileBytes, string keyBase64, string ivBase64, CipherMode mode, PaddingMode padding)
        {
            byte[] key = Convert.FromBase64String(keyBase64);
            byte[] iv = Convert.FromBase64String(ivBase64);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                if (mode != CipherMode.ECB) aes.IV = iv;
                aes.Mode = mode;
                aes.Padding = padding;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(fileBytes, 0, fileBytes.Length);
                        cs.FlushFinalBlock();
                    }
                    return ms.ToArray();
                }
            }
        }
    }
}