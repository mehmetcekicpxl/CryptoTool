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
            if(ModelState.IsValid)
            {
                ViewData["Hex"] = _hashingService.ComputeHash(hashAndText.Message, hashAndText.HashingType);
                hashAndText.Message = "";

                return View("Hashing", hashAndText);
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

            Stream filestream = hashAndText.fileToHash.OpenReadStream();
            ViewData["Hex"] = _hashingService.ComputeFileHash(filestream, hashAndText.HashingType);

            return View("FileHashing", hashAndText);
        }

        public IActionResult VerifyHex(HashingModel hashingModel)
        {
            if(ModelState.IsValid == false)
            {
                return View("Hashing", hashingModel);
            }

            if (_hashingService.VerifyHash(hashingModel.Message, hashingModel.Hex, hashingModel.HashingType))
            {
                ViewData["Status"] = "Hash klopt!";
            }

            else
            {
                ViewData["Status"] = "Hash klopt niet!";
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

            if (_hashingService.VerifyHashFile(hashingModel.fileToHash.OpenReadStream(), hashingModel.Hex, hashingModel.HashingType))
            {
                ViewData["Status"] = "Hash klopt!";
            }

            else
            {
                ViewData["Status"] = "Hash klopt niet!";
            }

            return View("FileHashing", hashingModel);
        }

        public IActionResult Hmac()
        {
            return View(new HmacModel());
        }

        public IActionResult CreateHmac(HmacModel hmacModel)
        {

            if (ModelState.IsValid)
            {
                hmacModel.Hex = _hashingService.HmacCreate(hmacModel.key, hmacModel.Message, hmacModel.HmacType);
                ViewData["hex"] = hmacModel.Hex;
                return View("Hmac", hmacModel);
            }


            return View("Hmac", hmacModel);
        }

        public IActionResult VerifyHmac(HmacModel hmacModel)
        {
            if(ModelState.IsValid == false)
            {
                return View("Hmac", hmacModel);
            }

            if (_hashingService.VerifyHmac(hmacModel.Message, hmacModel.Hex, hmacModel.key, hmacModel.HmacType))
            {
                ViewData["Result"] = "Hmac klopt!";
            }

            else
            {
                ViewData["Result"] = "Hmac klopt niet!";
            }

            return View("Hmac", hmacModel);
        }

        [HttpGet]
        public IActionResult HmacGenerateKey()
        {
            ViewData["key"] = _hashingService.HmacCreateKey();
            return View();
        }

    }
}
