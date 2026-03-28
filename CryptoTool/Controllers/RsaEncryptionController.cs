using Encryptie_H4.Models;
using Encryptie_H4.Models.RsaEncryption;
using Encryptie_H4.Services.RSARelated.Interfaces;
using Microsoft.AspNetCore.Mvc;
using System.Text;
using TextCopy;

namespace Encryptie_H4.Controllers
{
    public class RsaEncryptionController : Controller
    {
        private readonly IEncryptionService _encryptionService;
        public RsaEncryptionController(IEncryptionService encryptionService)
        {
            _encryptionService = encryptionService;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Encrypt()
        {
            return View(new KeyAndMessage());
        }

        [HttpPost]
        public IActionResult EncryptMessage(KeyAndMessage keyAndMessage)
        {
            try
            {
                RsaEncryptionResult result = _encryptionService.EncryptKey(keyAndMessage.Message, keyAndMessage.PublicKey);
                if (result.IsSuccesfull)
                {
                    keyAndMessage.EncryptedMessage = result.EncryptiondResult;
                    keyAndMessage.Message = "";

                    return View("Encrypt", keyAndMessage);
                }

                else
                {
                    keyAndMessage.EncryptedMessage = "Error(s): see below";
                    keyAndMessage.Message = null;

                    foreach (string error in result.GetErrors())
                    {
                        ModelState.AddModelError("", error);
                    }

                    return View("Encrypt", keyAndMessage);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[RSA Error] Encryption failed: {ex.Message}");
                ModelState.AddModelError("", "Er is een onverwachte fout opgetreden tijdens de versleuteling.");
                return View("Encrypt", keyAndMessage);
            }
            


        }

        public IActionResult DecryptMessage(KeyAndMessage keyAndMessage)
        {
            try
            {
                RsaEncryptionResult result = _encryptionService.DecryptKey(keyAndMessage.EncryptedMessage, keyAndMessage.PrivateKey);

                if (result.IsSuccesfull)
                {
                    keyAndMessage.Message = result.EncryptiondResult;
                    keyAndMessage.EncryptedMessage = "";
                    ViewBag.Result = "Decryptie succesvol!";
                    return View("Encrypt", keyAndMessage);

                }

                else
                {
                    keyAndMessage.Message = "Error(s): see below";

                    foreach (string error in result.GetErrors())
                    {
                        ModelState.AddModelError("", error);

                    }

                    ViewBag.succes = false;
                    return View("Encrypt", keyAndMessage);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[RSA Error] Decryption failed: {ex.Message}");
                ModelState.AddModelError("", "Fout bij ontsleutelen. Controleer of de private key bij dit bericht hoort.");
                return View("Encrypt", keyAndMessage);
            }
            
        }
        public IActionResult GenerateKeys()
        {
            try
            {
                KeyCollection pair = _encryptionService.GenerateKeys();

                return View("GenerateKeys", pair);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[RSA Error] Key generation failed: {ex.Message}");
                return View("GenerateKeys", new KeyCollection());
            }
            
        }

        public IActionResult GenerateKeysIndex()
        {
            return View("GenerateKeys", new KeyCollection());
        }

        public IActionResult CopyKey(int id)
        {
            try
            {
                ClipboardService.SetText(id.ToString());

                KeyCollection collection = _encryptionService.GetKeys();

                switch (id)
                {
                    case 0:
                        ClipboardService.SetText(collection.RsaPrivateKey);
                        break;
                    case 1:
                        ClipboardService.SetText(collection.RsaPublicKey);
                        break;
                    case 2:
                        ClipboardService.SetText(collection.AesKey);
                        break;
                }


                return View("GenerateKeys", collection);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Clipboard Error]: {ex.Message}");
                return View("GenerateKeys", _encryptionService.GetKeys() ?? new KeyCollection());
            }
            
        }

        public IActionResult DownloadAllKeys()
        {
            return Download();
        }


        public IActionResult Download()
        {
            try
            {
                if (_encryptionService.GetKeys() == null)
                {
                    return View("GenerateKeys", new KeyCollection());
                }

                KeyCollection collection = _encryptionService.GetKeys();


                StringBuilder sb = new();

                sb.AppendLine(collection.RsaPrivateKey);
                sb.AppendLine();

                sb.AppendLine(collection.RsaPublicKey);
                sb.AppendLine();

                sb.AppendLine("AES key");
                sb.AppendLine("--------------------");
                sb.AppendLine(collection.AesKey);

                var fileName = "my-file.txt";

                byte[] fileBytes = System.Text.Encoding.UTF8.GetBytes(sb.ToString());

                return File(fileBytes, "text/plain", fileName);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Download Error] Failed to download keys: {ex.Message}");
                return View("GenerateKeys", new KeyCollection());
            }
            
        }

        [HttpGet]
        public IActionResult Signature()
        {
            return View(new SignatureAndMessage());
        }

        [HttpPost]
        public IActionResult Signature(SignatureAndMessage signatureAndMessage)
        {
            try
            {
                RsaEncryptionResult result = _encryptionService.SignData(signatureAndMessage.Message, signatureAndMessage.RsaPrivateKey);

                if (result.IsSuccesfull)
                {
                    signatureAndMessage.Signature = result.EncryptiondResult;
                }

                else
                {
                    foreach (string error in result.GetErrors())
                    {
                        ModelState.AddModelError("", error);
                    }
                }

                return View(signatureAndMessage);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Signature Error] Signing failed: {ex.Message}");
                ModelState.AddModelError("", "Fout tijdens het ondertekenen van het bericht.");
                return View(signatureAndMessage);
            }
            
        }

        public IActionResult VerifySignature(SignatureAndMessage signatureAndMessage)
        {
            try
            {
                RsaEncryptionResult result = _encryptionService.VerifySignature(signatureAndMessage.Message, signatureAndMessage.Signature, signatureAndMessage.RsaPublicKey);
                signatureAndMessage.IsValid = result.IsSuccesfull;

                if (!result.IsSuccesfull)
                {
                    ViewBag.Fail = "Signature klopt niet!!!";
                }


                return View("Signature", signatureAndMessage);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Signature Error] Verification failed: {ex.Message}");
                ViewBag.Fail = "Fout bij verificatie. Controleer of de sleutel en handtekening correct zijn geplakt.";
                signatureAndMessage.IsValid = false;
                return View("Signature", signatureAndMessage);
            }
            
        }


    }
}

