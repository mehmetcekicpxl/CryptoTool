namespace CryptoTool.ViewModels.Advanced
{
    public class HybridEncryptionViewModel
    {
        public string? HybridInputMessage { get; set; }
        public string? HybridPublicKey { get; set; }
        public string? HybridEncryptedMessage { get; set; }
        public string? HybridEncryptedSessionKey { get; set; }
        public string? HybridIv { get; set; }
        public string? HybridError { get; set; }
    }
}
