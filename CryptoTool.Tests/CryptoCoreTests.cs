using CryptoTool.Services;
using Encryptie_H4.Services;
using System.Security.Authentication;
using System.Security.Cryptography;
using static Encryptie_H4.Services.HashingService;

namespace CryptoTool.Tests
{
    public class CryptoCoreTests
    {
        private readonly AesEncryptionService _aesService;
        private readonly RsaKeyService _rsaService;
        private readonly HashingService _hashingService;
        public CryptoCoreTests()
        {
            _aesService = new AesEncryptionService();
            _rsaService = new RsaKeyService();
            _hashingService = new HashingService();
        }
        [Fact]
        public void AesEncryption_ShouldChangePlainText()
        {
            string plainText = "TestMessage123";
            string key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            string iv = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));

            var result = _aesService.Encrypt(plainText, key, iv, CipherMode.CBC, PaddingMode.PKCS7);

            // Verifies that the encrypted text is not the same as the original text
            Assert.NotEqual(plainText, result.CipherText);
            Assert.NotNull(result.CipherText);
        }
        [Fact]
        public void AesDecryption_ShouldRestoreOriginalText()
        {
            string originalText = "TopSecretData";
            string key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            string iv = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));

            var encrypted = _aesService.Encrypt(originalText, key, iv, CipherMode.CBC, PaddingMode.PKCS7);
            string decrypted = _aesService.Decrypt(encrypted.CipherText, key, iv, CipherMode.CBC, PaddingMode.PKCS7);

            Assert.Equal(originalText, decrypted);
        }

        [Fact]
        public void AesDecryption_WithWrongKey_ShouldThrowException()
        {
            string originalText = "Data";
            string correctKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            string wrongKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            string iv = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));

            var encrypted = _aesService.Encrypt(originalText, correctKey, iv, CipherMode.CBC, PaddingMode.PKCS7);

            // Expects a cryptographic exception when decrypting with the wrong key
            Assert.ThrowsAny<CryptographicException>(() =>
                _aesService.Decrypt(encrypted.CipherText, wrongKey, iv, CipherMode.CBC, PaddingMode.PKCS7)
            );
        }

        [Fact]
        public void RsaKeyGeneration_ShouldReturnValidKeySizes()
        {
            int keySize = 2048;
            var keyPair = _rsaService.GenerateKeyPair(keySize);

            Assert.NotNull(keyPair.PublicKey);
            Assert.NotNull(keyPair.PrivateKey);

            // Checks if the generated keys contain the correct PKCS#1 format headers
            Assert.Contains("BEGIN RSA PUBLIC KEY", keyPair.PublicKey);
            Assert.Contains("BEGIN RSA PRIVATE KEY", keyPair.PrivateKey);
        }

        [Fact]
        public void RsaKeyGeneration_InvalidSize_ShouldThrowException()
        {
            // RSA requires key sizes in specific increments, 123 is invalid
            Assert.ThrowsAny<Exception>(() => _rsaService.GenerateKeyPair(123));
        }

        [Fact]
        public void Hashing_Sha256_ShouldReturnConsistentHash()
        {
            string input = "TestString";

            string hash1 = _hashingService.ComputeHash(input, HashAlgorithmType.Sha256);
            string hash2 = _hashingService.ComputeHash(input, HashAlgorithmType.Sha256);

            // Hashing the exact same input twice must yield the exact same output
            Assert.Equal(hash1, hash2);
            Assert.NotEmpty(hash1);
        }

        [Fact]
        public void Hashing_DifferentInputs_ShouldReturnDifferentHashes()
        {
            string hash1 = _hashingService.ComputeHash("InputA", HashAlgorithmType.Sha256);
            string hash2 = _hashingService.ComputeHash("InputB", HashAlgorithmType.Sha256);

            Assert.NotEqual(hash1, hash2);
        }

        [Fact]
        public void VerifyHash_WithCorrectData_ShouldReturnTrue()
        {
            string input = "VerifyMe";
            string computedHash = _hashingService.ComputeHash(input, HashAlgorithmType.Sha512);

            bool isValid = _hashingService.VerifyHash(input, computedHash, HashAlgorithmType.Sha512);

            Assert.True(isValid);
        }

        [Fact]
        public void HmacCreation_ShouldRequireKey()
        {
            string message = "HmacMessage";
            string secretKey = "SuperSecret123";

            string hmac = _hashingService.HmacCreate(secretKey, message, HmacType.HMACSHA256);

            Assert.NotNull(hmac);
            Assert.True(hmac.Length > 0);
        }

        [Fact]
        public void VerifyHmac_WithTamperedMessage_ShouldReturnFalse()
        {
            string message = "Original";
            string secretKey = "Key123";
            string validHmac = _hashingService.HmacCreate(secretKey, message, HmacType.HMACSHA256);

            // Simulates a man-in-the-middle changing the message text
            string tamperedMessage = "Original-Altered";
            bool isValid = _hashingService.VerifyHmac(tamperedMessage, validHmac, secretKey, HmacType.HMACSHA256);

            Assert.False(isValid);
        }
    }
}
