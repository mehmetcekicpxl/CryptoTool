using System.ComponentModel.DataAnnotations;

namespace Encryptie_H4.Models.RsaEncryption
{
    public class KeyAndMessage
    {
        [Required]
        public string PublicKey { get; set; }
        [Required]
        public string PrivateKey { get; set; }
        [Required]
        public string Message { get; set; }
        [Required]
        public string EncryptedMessage { get; set; }
    }
}
