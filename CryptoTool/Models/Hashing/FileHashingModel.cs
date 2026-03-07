using Microsoft.Extensions.FileProviders;
using System.ComponentModel.DataAnnotations;
using System.Security.Authentication;

namespace Encryptie_H4.Models.Hashing
{
    public class FileHashingModel
    {
        [Required]
        public IFormFile fileToHash { get; set; }
        public string Hex { get; set; } = "";
        [Required]
        public HashAlgorithmType HashingType { get; set; }
    }
}
