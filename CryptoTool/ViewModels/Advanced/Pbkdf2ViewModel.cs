namespace CryptoTool.ViewModels.Advanced
{
    public class Pbkdf2ViewModel
    {
        public string? InputPassword { get; set; }
        public string? InputSalt { get; set; }
        public int InputIterations { get; set; } = 100000;
        public string? DerivedKey { get; set; }
        public string? DeriveError { get; set; }
    }
}
