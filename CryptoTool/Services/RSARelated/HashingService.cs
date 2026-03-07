

using Encryptie_H4.Services.RSARelated.Interfaces;
using System.Runtime.Intrinsics.Arm;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Encryptie_H4.Services
{
    public class HashingService : IHashingService
    {
        public string ComputeHash(string input, HashAlgorithmType type)
        {
            HashAlgorithm hashAlgorithm = MakeHashAlgo(type);

            byte[] data = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(input));

            // Create a new Stringbuilder to collect the bytes
            // and create a string.
            var sBuilder = new StringBuilder();

            // Loop through each byte of the hashed data
            // and format each one as a hexadecimal string.
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            // Return the hexadecimal string.
            return sBuilder.ToString();
        }

        public string ComputeFileHash(Stream fileStream, HashAlgorithmType type)
        {

            using (fileStream)
            {
                HashAlgorithm hashAlgorithm = MakeHashAlgo(type);

                try
                {
                    // Create a fileStream for the file.
                    // Be sure it's positioned to the beginning of the stream.
                    fileStream.Position = 0;
                    // Compute the hash of the fileStream.
                    byte[] hashValue = hashAlgorithm.ComputeHash(fileStream);

                    StringBuilder stringBuilder = new StringBuilder();

                    // Loop through each byte of the hashed data
                    // and format each one as a hexadecimal string.
                    for (int i = 0; i < hashValue.Length; i++)
                    {
                        stringBuilder.Append(hashValue[i].ToString("x2"));
                    }

                    return stringBuilder.ToString();
                }

                catch
                {
                    return "ERROR";
                }
            }
        }
        public bool VerifyHash(string input, string expectedHash, HashAlgorithmType type)
        {
            // Hash the input.
            var hashOfInput = ComputeHash(input, type);

            // Create a StringComparer an compare the hashes.
            StringComparer comparer = StringComparer.OrdinalIgnoreCase;

            return comparer.Compare(hashOfInput, expectedHash) == 0;
        }

        public bool VerifyHashFile(Stream input, string expectedHash, HashAlgorithmType type)
        {
            // Hash the input.
            var hashOfInput = ComputeFileHash(input, type);

            // Create a StringComparer an compare the hashes.
            StringComparer comparer = StringComparer.OrdinalIgnoreCase;

            return comparer.Compare(hashOfInput, expectedHash) == 0;
        }

        private HashAlgorithm MakeHashAlgo(HashAlgorithmType type)
        {
            HashAlgorithm hashAlgorithm;

            switch (type)
            {
                case HashAlgorithmType.Md5:
                    return hashAlgorithm = MD5.Create();

                case HashAlgorithmType.Sha1:
                    return hashAlgorithm = SHA1.Create();

                case HashAlgorithmType.Sha256:
                    return hashAlgorithm = SHA256.Create();

                case HashAlgorithmType.Sha384:
                    return hashAlgorithm = SHA384.Create();

                case HashAlgorithmType.Sha512:
                    return hashAlgorithm = SHA512.Create();

                default:
                    return hashAlgorithm = SHA256.Create();
            }
        }


        public string HmacCreate(string key, string message, HmacType type)
        {

            // Convert key and message to byte arrays
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] data = Encoding.UTF8.GetBytes(message);

            return type switch
            {
                HmacType.HMACSHA256 => Convert.ToBase64String(HMACSHA256.HashData(keyBytes, data)),
                HmacType.HMACSHA384 => Convert.ToBase64String(HMACSHA384.HashData(keyBytes, data)),
                HmacType.HMACSHA512 => Convert.ToBase64String(HMACSHA512.HashData(keyBytes, data)), 
                _ => throw new NotSupportedException()
            };
        }

        public string GenerateHmacKey(HmacType type)
        {
            switch (type)
            {
                case HmacType.HMACSHA256:
                    return Convert.ToBase64String(new HMACSHA256().Key);
                  
                case HmacType.HMACSHA384:
                    return Convert.ToBase64String(new HMACSHA384().Key);                

                default:
                    return Convert.ToBase64String(new HMACSHA512().Key);
            }
        }

        public bool VerifyHmac(string message, string expectedHash, string key, HmacType type)
        {
            string hash = HmacCreate(key, message, type);

            StringComparer comparer = StringComparer.OrdinalIgnoreCase;

            return comparer.Compare(hash, expectedHash) == 0;
        }

        public string HmacCreateKey()
        {
            byte[] secretkey = new Byte[64];

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                // The array is now filled with cryptographically strong random bytes.
                rng.GetBytes(secretkey);
            }

            return Convert.ToBase64String(secretkey);
        }

        public enum HmacType
        {
            HMACSHA256,
            HMACSHA384,
            HMACSHA512
        }
    }
}

