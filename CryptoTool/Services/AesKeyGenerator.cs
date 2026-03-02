using System.Security.Cryptography;
using CryptoTool.Models; 

namespace CryptoTool.Services
{
   
    public class AesKeyGenerator
    {
       
        public AesKeyPair GenerateKey(int keySize)
        {
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = keySize;
                aes.GenerateKey();
                aes.GenerateIV();

                
                return new AesKeyPair
                {
                    Key = aes.Key,
                    IV = aes.IV
                };
            }
        }

       
        public string ExportKeyToBase64(byte[] key)
        {
            return Convert.ToBase64String(key);
        }

       
        public string ExportKeyToHex(byte[] key)
        {
            return Convert.ToHexString(key);
        }
    }
}