namespace CryptoTool.Models
{
    public class EncryptionResult
    {
        public string CipherText { get; set; } 
        public string IV { get; set; }
        public string Mode { get; set; }
    }
}
