using CryptoTool.Services;
using CryptoTool.Models;
using Microsoft.AspNetCore.Mvc;
using System.Text;

namespace CryptoTool.Controllers
{
    public class KeyGeneratorController : Controller
    {
        
        private readonly AesKeyGenerator _aesGenerator;
        private readonly RsaKeyService _rsaService;

        public KeyGeneratorController()
        {
            _aesGenerator = new AesKeyGenerator();
            _rsaService = new RsaKeyService();
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public IActionResult GenerateAes(int keySize)
        {
           
            AesKeyPair keyPair = _aesGenerator.GenerateKey(keySize);

            
            string keyBase64 = _aesGenerator.ExportKeyToBase64(keyPair.Key);
            string ivBase64 = _aesGenerator.ExportKeyToBase64(keyPair.IV);
            string keyHex = _aesGenerator.ExportKeyToHex(keyPair.Key);

            ViewBag.AesKeyBase64 = keyBase64;
            ViewBag.AesIVBase64 = ivBase64;
            ViewBag.AesKeyHex = keyHex;
            ViewBag.SelectedKeySize = keySize;

            return View("Index");
        }

        
        [HttpPost]
        public IActionResult DownloadAesKey(string keyBase64, string ivBase64)
        {
            if (string.IsNullOrEmpty(keyBase64) || string.IsNullOrEmpty(ivBase64))
            {
                return RedirectToAction("Index");
            }

            //slaan de sleutel en IV op in een tekstbestand.
            var content = $"AES Key (Base64): {keyBase64}\nAES IV (Base64): {ivBase64}";
            var bytes = Encoding.UTF8.GetBytes(content);
            var output = new MemoryStream(bytes);

            return File(output, "text/plain", "aes_keys.txt");
        }

        [HttpPost]
        public IActionResult GenerateRsa(int keySize)
        {
            var result = _rsaService.GenerateKeyPair(keySize);

            ViewBag.RsaPublicKey = result.PublicKey;
            ViewBag.RsaPrivateKey = result.PrivateKey;
            ViewBag.SelectedRsaKeySize = keySize;

            return View("Index");
        }
       
        [HttpPost]
        public IActionResult DownloadRsaPublicKey(string publicKey)
        {
            if (string.IsNullOrEmpty(publicKey)) return RedirectToAction("Index");

            var bytes = Encoding.UTF8.GetBytes(publicKey);
            var output = new MemoryStream(bytes);
            return File(output, "application/x-pem-file", "public_key.pem");
        }

        
        [HttpPost]
        public IActionResult DownloadRsaPrivateKey(string privateKey)
        {
            if (string.IsNullOrEmpty(privateKey)) return RedirectToAction("Index");

            var bytes = Encoding.UTF8.GetBytes(privateKey);
            var output = new MemoryStream(bytes);
            return File(output, "application/x-pem-file", "private_key.pem");
        }
    }
}