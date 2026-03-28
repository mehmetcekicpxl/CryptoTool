namespace CryptoTool.Services.Advanced.Interfaces
{
    public interface IAdvancedCryptoService
    {
        string GenerateSecurePassword(int length, bool useNumbers, bool useSymbols);
        string DeriveKeyPbkdf2(string password, string saltBase64, int iterations);
        (string EncryptedMessage, string EncryptedSessionKey, string Iv) EncryptHybrid(string plainText, string rsaPublicKeyPem);
    }
}
