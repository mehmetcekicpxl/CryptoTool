using CryptoTool.Services;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;

namespace CryptoTool.Controllers
{
    public class EncryptionController : Controller
    {
        private readonly AesEncryptionService _encryptionService;

        public EncryptionController()
        {
            _encryptionService = new AesEncryptionService();
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Encrypt(string plainText, string key, string iv, string mode, string padding)
        {
            try
            {
                
                CipherMode cipherMode = Enum.Parse<CipherMode>(mode);
                PaddingMode paddingMode = Enum.Parse<PaddingMode>(padding);

                var result = _encryptionService.Encrypt(plainText, key, iv, cipherMode, paddingMode);

                ViewBag.Result = result.CipherText;
                ViewBag.Message = "Versleuteling succesvol! (Encryptie geslaagd)";
            }
            catch (Exception ex)
            {
                ViewBag.Error = "Fout: " + ex.Message;
            }

           
            ViewBag.PlainText = plainText;
            ViewBag.Key = key;
            ViewBag.IV = iv;
            ViewBag.SelectedMode = mode;
            ViewBag.SelectedPadding = padding;

            return View("Index");
        }

        [HttpPost]
        public IActionResult Decrypt(string cipherText, string key, string iv, string mode, string padding)
        {
            try
            {
                CipherMode cipherMode = Enum.Parse<CipherMode>(mode);
                PaddingMode paddingMode = Enum.Parse<PaddingMode>(padding);

                string plainText = _encryptionService.Decrypt(cipherText, key, iv, cipherMode, paddingMode);

                ViewBag.DecryptedResult = plainText;
                ViewBag.DecryptMessage = "Ontsleuteling succesvol! (Decryptie geslaagd)";
            }
            catch (Exception ex)
            {
                ViewBag.DecryptError = "Fout bij ontsleutelen. Controleer uw sleutel, IV en modus.";
            }

            ViewBag.CipherTextInput = cipherText;
            ViewBag.KeyDecrypt = key;
            ViewBag.IVDecrypt = iv;
            ViewBag.SelectedModeDecrypt = mode;
            ViewBag.SelectedPaddingDecrypt = padding;

            return View("Index");
        }

      
    }
}