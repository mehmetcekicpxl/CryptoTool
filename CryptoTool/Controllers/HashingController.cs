using Encryptie_H4.Models.Hashing;
using Encryptie_H4.Services.RSARelated.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace Encryptie_H4.Controllers
{
    public class HashingController : Controller
    {
        private readonly IHashingService _hashingService;

        public HashingController(IHashingService hashingService)
        {
            _hashingService = hashingService;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Hashing()
        {
            return View(new HashingModel());
        }

        [HttpPost]
        public IActionResult HashText(HashingModel hashAndText)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    ViewData["Hex"] = _hashingService.ComputeHash(hashAndText.Message, hashAndText.HashingType);
                    hashAndText.Message = "";

                    return View("Hashing", hashAndText);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Hashing Error] Text hashing failed: {ex.Message}");
                ModelState.AddModelError("", "Er is een fout opgetreden bij het berekenen van de hash.");
            }
            return View("Hashing", hashAndText);

        }

        [HttpGet]
        public IActionResult FileHashing()
        {
            return View("FileHashing", new FileHashingModel());
        }

        [HttpPost]
        public IActionResult FileHashing(FileHashingModel hashAndText)
        {
            if (hashAndText.fileToHash is null)
            {
                ModelState.AddModelError("", "Kies een file!");
                return View("FileHashing", hashAndText);
            }

            try
            {
                Stream filestream = hashAndText.fileToHash.OpenReadStream();
                ViewData["Hex"] = _hashingService.ComputeFileHash(filestream, hashAndText.HashingType);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Hashing Error] File hashing failed: {ex.Message}");
                ModelState.AddModelError("", "Fout bij het lezen van het bestand. Mogelijk is het bestand beschadigd of vergrendeld.");
            }
            return View("FileHashing", hashAndText);
        }

        public IActionResult VerifyHex(HashingModel hashingModel)
        {
            if(ModelState.IsValid == false)
            {
                return View("Hashing", hashingModel);
            }

            try
            {
                if (_hashingService.VerifyHash(hashingModel.Message, hashingModel.Hex, hashingModel.HashingType))
                {
                    ViewData["Status"] = "Hash klopt!";
                }

                else
                {
                    ViewData["Status"] = "Hash klopt niet!";
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Hashing Error] Hex verification failed: {ex.Message}");
                ViewData["Status"] = "Verificatie mislukt door een onverwachte fout.";
            }
            return View("Hashing", hashingModel);

        }

        public IActionResult VerifyFileHex(FileHashingModel hashingModel)
        {
            if (hashingModel.fileToHash is null)
            {
                ModelState.AddModelError("", "Kies een file!");
                return View("FileHashing", hashingModel);
            }

            try
            {
                if (_hashingService.VerifyHashFile(hashingModel.fileToHash.OpenReadStream(), hashingModel.Hex, hashingModel.HashingType))
                {
                    ViewData["Status"] = "Hash klopt!";
                }

                else
                {
                    ViewData["Status"] = "Hash klopt niet!";
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Hashing Error] File hex verification failed: {ex.Message}");
                ViewData["Status"] = "Bestand verificatie mislukt. Controleer de invoer.";
            }
            

            return View("FileHashing", hashingModel);
        }

        public IActionResult Hmac()
        {
            return View(new HmacModel());
        }

        public IActionResult CreateHmac(HmacModel hmacModel)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    hmacModel.Hex = _hashingService.HmacCreate(hmacModel.key, hmacModel.Message, hmacModel.HmacType);
                    ViewData["hex"] = hmacModel.Hex;
                    return View("Hmac", hmacModel);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[HMAC Error] Creation failed: {ex.Message}");
                ModelState.AddModelError("", "Fout bij het genereren van de HMAC.");
            }
            return View("Hmac", hmacModel);
        }

        public IActionResult VerifyHmac(HmacModel hmacModel)
        {
            if(ModelState.IsValid == false)
            {
                return View("Hmac", hmacModel);
            }

            try
            {
                if (_hashingService.VerifyHmac(hmacModel.Message, hmacModel.Hex, hmacModel.key, hmacModel.HmacType))
                {
                    ViewData["Result"] = "Hmac klopt!";
                }

                else
                {
                    ViewData["Result"] = "Hmac klopt niet!";
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[HMAC Error] Verification failed: {ex.Message}");
                ViewData["Result"] = "Fout tijdens het verifiëren van de HMAC.";
            }
            return View("Hmac", hmacModel);
        }

        [HttpGet]
        public IActionResult HmacGenerateKey()
        {
            try
            {
                ViewData["key"] = _hashingService.HmacCreateKey();
            }
            catch (Exception ex)
            {

                Console.WriteLine($"[HMAC Error] Key generation failed: {ex.Message}");
                ViewData["key"] = "Error generating key.";
            }
            
            return View();
        }

    }
}
