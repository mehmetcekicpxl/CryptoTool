namespace CryptoTool.ViewModels.Advanced
{
    public class PasswordGeneratorViewModel
    {
        public int PwdLength { get; set; } = 16;
        public bool UseNumbers { get; set; } = true;
        public bool UseSymbols { get; set; } = true;
        public string? GeneratedPassword { get; set; }
        public string? PasswordError { get; set; }
    }
}
