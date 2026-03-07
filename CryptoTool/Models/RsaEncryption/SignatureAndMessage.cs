using System.ComponentModel.DataAnnotations;

namespace Encryptie_H4.Models.RsaEncryption
{
    public class SignatureAndMessage
    {
      
        public bool IsValid { get; set; }
        [Required]
        public string Message { get; set; }
        [Required]
        public string Signature { get; set; }
        [Required]
        public string RsaPrivateKey { get; set; }
        [Required]
        public string RsaPublicKey { get; set; }
    }
}
