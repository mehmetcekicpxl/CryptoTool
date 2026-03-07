using Microsoft.Extensions.FileProviders;
using System.ComponentModel.DataAnnotations;
using System.Security.Authentication;
using static Encryptie_H4.Services.HashingService;

namespace Encryptie_H4.Models.Hashing
{
    public class HmacModel
    {
        [Required]
        public string key { get; set; }
        [Required]
        public string Hex { get; set; }
        [Required]
        public string Message { get; set; } = "";
        [Required]
        public HmacType HmacType { get; set; }
    }
}
