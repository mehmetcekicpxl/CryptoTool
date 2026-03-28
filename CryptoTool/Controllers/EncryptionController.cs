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
                Console.WriteLine($"[Encryption Error] Encrypt failed: {ex.Message}");

                ViewBag.Error = "Er is een fout opgetreden bij het versleutelen. Controleer of de invoer correct is.";
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
                Console.WriteLine($"[Encryption Error] Decrypt failed: {ex.Message}");

                ViewBag.Error = "Fout bij ontsleutelen. Controleer uw sleutel, IV en modus.";
            }

            ViewBag.CipherTextInput = cipherText;
            ViewBag.KeyDecrypt = key;
            ViewBag.IVDecrypt = iv;
            ViewBag.SelectedModeDecrypt = mode;
            ViewBag.SelectedPaddingDecrypt = padding;

            return View("Index");
        }

      
        [HttpPost]
        public IActionResult EncryptFile(IFormFile file, string key, string iv, string mode, string padding)
        {
            if (file == null || file.Length == 0)
            {
                ViewBag.Error = "Selecteer alstublieft een bestand.";
                return View("Index");
            }

            try
            {
                CipherMode cipherMode = Enum.Parse<CipherMode>(mode);
                PaddingMode paddingMode = Enum.Parse<PaddingMode>(padding);

                // Lees het bestand in een byte-array
                byte[] fileBytes;
                using (var ms = new MemoryStream())
                {
                    file.CopyTo(ms);
                    fileBytes = ms.ToArray();
                }

               
                byte[] encryptedBytes = _encryptionService.EncryptFile(fileBytes, key, iv, cipherMode, paddingMode);

                // Download het versleutelde bestand (voeg .enc toe aan de naam)
                string fileName = file.FileName + ".enc";
                return File(encryptedBytes, "application/octet-stream", fileName);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Encryption Error] File Encrypt failed: {ex.Message}");
                ViewBag.Error = "Fout bij bestand versleuteling. Controleer of de bestandsgrootte en sleutels kloppen.";
                return View("Index");
            }
        }

       
        [HttpPost]
        public IActionResult DecryptFile(IFormFile file, string key, string iv, string mode, string padding)
        {
            if (file == null || file.Length == 0)
            {
                ViewBag.Error = "Selecteer alstublieft een bestand.";
                return View("Index");
            }

            try
            {
                CipherMode cipherMode = Enum.Parse<CipherMode>(mode);
                PaddingMode paddingMode = Enum.Parse<PaddingMode>(padding);

                byte[] fileBytes;
                using (var ms = new MemoryStream())
                {
                    file.CopyTo(ms);
                    fileBytes = ms.ToArray();
                }

                // Ontsleutel het bestand
                byte[] decryptedBytes = _encryptionService.DecryptFile(fileBytes, key, iv, cipherMode, paddingMode);

                // Verwijder de .enc extensie als die bestaat
                string fileName = file.FileName.Replace(".enc", "");
                // Als er geen .enc was, voeg .decrypted toe om overschrijven te voorkomen
                if (fileName == file.FileName) fileName = "decrypted_" + file.FileName;

                return File(decryptedBytes, "application/octet-stream", fileName);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Encryption Error] File Decrypt failed: {ex.Message}");
                ViewBag.Error = "Fout bij bestand ontsleuteling. Controleer de sleutel en het IV!";
                return View("Index");
            }
        }
    }
}