namespace CryptoTool.ViewModels.Advanced
{
    public class AdvancedPageViewModel
    {
        public PasswordGeneratorViewModel PasswordModel { get; set; } = new();
        public Pbkdf2ViewModel Pbkdf2Model { get; set; } = new();
        public HybridEncryptionViewModel HybridModel { get; set; } = new();
    }
}
