using CryptoTool.Services.Advanced;
using Microsoft.AspNetCore.Mvc;
using CryptoTool.Services.Advanced.Interfaces;
using CryptoTool.ViewModels.Advanced;


namespace CryptoTool.Controllers
{
    public class AdvancedController : Controller
    {
        private readonly IAdvancedCryptoService _advancedService;

        public AdvancedController(IAdvancedCryptoService advancedService)
        {
            _advancedService = advancedService;
        }

        [HttpGet]
        public IActionResult Index()
        {
            // Passes an empty ViewModel to the view on first load
            return View(new AdvancedPageViewModel());
        }

        [HttpPost]
        public IActionResult GeneratePassword(AdvancedPageViewModel pageModel)
        {
            try
            {
                if (pageModel.PasswordModel.PwdLength < 8 || pageModel.PasswordModel.PwdLength > 128)
                {
                    pageModel.PasswordModel.PasswordError = "Lengte moet tussen 8 en 128 tekens zijn.";
                    return View("Index", pageModel);
                }

                // Generates the secure password using the injected service
                pageModel.PasswordModel.GeneratedPassword = _advancedService.GenerateSecurePassword(
                    pageModel.PasswordModel.PwdLength,
                    pageModel.PasswordModel.UseNumbers,
                    pageModel.PasswordModel.UseSymbols);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Advanced Error] Password Gen failed: {ex.Message}");
                pageModel.PasswordModel.PasswordError = "Er ging iets mis bij het genereren van het wachtwoord.";
            }

            return View("Index", pageModel);
        }

        [HttpPost]
        public IActionResult DeriveKey(AdvancedPageViewModel pageModel)
        {
            try
            {
                if (string.IsNullOrEmpty(pageModel.Pbkdf2Model.InputSalt))
                {
                    pageModel.Pbkdf2Model.DeriveError = "Een Base64 salt is verplicht.";
                    return View("Index", pageModel);
                }

                if (string.IsNullOrEmpty(pageModel.Pbkdf2Model.InputPassword))
                {
                    pageModel.Pbkdf2Model.DeriveError = "Een wachtwoord is verplicht.";
                    return View("Index", pageModel);
                }

                // Derives the 256-bit AES key via PBKDF2
                pageModel.Pbkdf2Model.DerivedKey = _advancedService.DeriveKeyPbkdf2(
                    pageModel.Pbkdf2Model.InputPassword,
                    pageModel.Pbkdf2Model.InputSalt,
                    pageModel.Pbkdf2Model.InputIterations);
            }
            catch (FormatException)
            {
                Console.WriteLine("[Advanced Error] Invalid Base64 salt provided.");
                pageModel.Pbkdf2Model.DeriveError = "De salt moet een geldige Base64 string zijn.";
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Advanced Error] PBKDF2 failed: {ex.Message}");
                pageModel.Pbkdf2Model.DeriveError = "Fout bij het afleiden van de sleutel. Controleer je invoer.";
            }

            return View("Index", pageModel);
        }
        [HttpPost]
        public IActionResult HybridEncrypt(AdvancedPageViewModel pageModel)
        {
            try
            {
                if (string.IsNullOrEmpty(pageModel.HybridModel.HybridInputMessage) || string.IsNullOrEmpty(pageModel.HybridModel.HybridPublicKey))
                {
                    pageModel.HybridModel.HybridError = "Bericht en RSA Public Key zijn verplicht.";
                    return View("Index", pageModel);
                }

                // Executes the hybrid encryption flow
                var result = _advancedService.EncryptHybrid(
                    pageModel.HybridModel.HybridInputMessage,
                    pageModel.HybridModel.HybridPublicKey);

                pageModel.HybridModel.HybridEncryptedMessage = result.EncryptedMessage;
                pageModel.HybridModel.HybridEncryptedSessionKey = result.EncryptedSessionKey;
                pageModel.HybridModel.HybridIv = result.Iv;
            }
            catch (Exception ex)
            {
                // Logs the specific error to the server console for debugging
                Console.WriteLine($"[Advanced Error] Hybrid Encryption failed: {ex.Message}");
                pageModel.HybridModel.HybridError = "Fout bij hybride versleuteling. Controleer of de ingevoerde RSA Public Key het juiste PEM formaat heeft.";
            }

            return View("Index", pageModel);
        }
    }
}
