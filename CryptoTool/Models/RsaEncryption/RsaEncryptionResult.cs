namespace Encryptie_H4.Models.RsaEncryption
{
    public class RsaEncryptionResult
    {
        private List<string> Errors { get; set; } = new();
        public string Message { get; set; }
        public bool IsSuccesfull { get; set; }
        public string EncryptiondResult { get; set; }

        public void AddError(string error)
        {
            Errors.Add(error);
        }

        public IEnumerable<string> GetErrors()
        {
            return Errors;
        }
    }
}
