using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http.Json;
using System.Security.Claims;
using XcelerateLinks.Models.ViewModels;
using APIPSI16.Services;

namespace XcelerateLinks.Mvc.Controllers
{
    public class AccountController : BaseController
    {
        private readonly IHttpClientFactory _httpFactory;
        private readonly ILogger<AccountController> _logger;
        private readonly IWebHostEnvironment _env;
        private readonly PasswordResetService _passwordResetService;
        private readonly IEmailSender _emailSender;
        private readonly IUserService _userService;
        private const string CookieName = "ApiAccessToken";

        public AccountController(
            IHttpClientFactory httpFactory,
            ILogger<AccountController> logger,
            IWebHostEnvironment env,
            ISessionService sessionService,
            PasswordResetService passwordResetService,
            IEmailSender emailSender,
            IUserService userService
        )
            : base(sessionService)
        {
            _httpFactory = httpFactory;
            _logger = logger;
            _env = env;
            _passwordResetService = passwordResetService;
            _emailSender = emailSender;
            _userService = userService;
        }

        [HttpGet]
        public IActionResult Login(string? returnUrl = null)
        {
            if (User.Identity?.IsAuthenticated == true)
            {
                var roleClaim = User.FindFirst(ClaimTypes.Role)?.Value;
                if (!string.IsNullOrWhiteSpace(roleClaim) && roleClaim == "0")
                    return RedirectToAction("AdminIndex", "Home");
                return RedirectToAction("Index", "Home");
            }
            return View(new LoginViewModel { ReturnUrl = returnUrl });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            if (!ModelState.IsValid)
                return View(model);
            try
            {
                var client = _httpFactory.CreateClient("Api");
                var payload = new
                {
                    username = model.Username,
                    password = model.Password
                };
                var resp = await client.PostAsJsonAsync("api/auth/login", payload);
                if (!resp.IsSuccessStatusCode)
                {
                    ModelState.AddModelError(string.Empty, "Utilizador ou senha inválidos.");
                    return View(model);
                }
                var authResponse = await resp.Content.ReadFromJsonAsync<AuthResponse>();
                if (authResponse?.Token == null)
                {
                    ModelState.AddModelError(string.Empty, "Erro ao obter token.");
                    return View(model);
                }
                // ── Token Storage — two-layer strategy ───────────────────────────────────
                //
                // The API returns a signed JWT in the JSON response body.
                // The MVC front-end then stores it in TWO places:
                //
                //  1. An HttpOnly browser cookie  ("ApiAccessToken")
                //     — used to forward the raw JWT to the REST API on every HTTP call.
                //     — HttpOnly means JavaScript cannot read it (XSS protection).
                //     — Secure=true on HTTPS connections (prevents interception over HTTP).
                //
                //  2. ASP.NET Core cookie authentication (via SignInAsync)
                //     — stores a trimmed set of claims (userId, username, role) that the
                //       MVC layer uses for [Authorize] checks and User.FindFirst(...) calls.
                //     — This is a separate, encrypted .AspNetCore.Cookies cookie.
                //     — Does NOT store the full JWT; that lives only in "ApiAccessToken".
                //
                // A matching server-side record is also written to the Sessions SQL table
                // (via _sessionService.CreateSessionAsync) so that the server can revoke
                // a session immediately without waiting for the cookie to expire.
                // ─────────────────────────────────────────────────────────────────────────

                // Parse the JWT to extract claims embedded by the API (userId, username, role).
                var jwtHandler = new JwtSecurityTokenHandler();
                var token = jwtHandler.ReadJwtToken(authResponse.Token);
                var userIdClaim = token.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
                var usernameClaim = token.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
                var roleClaim = token.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;

                if (string.IsNullOrWhiteSpace(userIdClaim) || !int.TryParse(userIdClaim, out var userId))
                {
                    ModelState.AddModelError(string.Empty, "Token inválido.");
                    return View(model);
                }

                // Server side: invalidate any existing session for this user, then create a
                // new one. This ensures only one active session exists at a time (single-device
                // policy). The raw JWT string is stored in the Sessions table alongside its
                // expiry so the server can validate or revoke it on each request.
                await _sessionService.InvalidateAllUserSessionsAsync(userId);
                var expiresAt = DateTimeOffset.UtcNow.AddHours(1).DateTime;
                await _sessionService.CreateSessionAsync(userId, authResponse.Token, expiresAt);

                // Client side — STORAGE #1: HttpOnly cookie named "ApiAccessToken".
                // This cookie carries the raw JWT to the browser. Every subsequent MVC
                // request includes it automatically; TokenHandler reads it and adds it as
                // an Authorization: Bearer header on outbound calls to the REST API.
                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true,             // JavaScript cannot access this cookie
                    Secure = Request.IsHttps,    // Send only over HTTPS when available
                    SameSite = SameSiteMode.Lax, // Sent on same-site navigations; blocks CSRF from cross-origin POSTs
                    Expires = DateTimeOffset.UtcNow.AddHours(1)
                };
                Response.Cookies.Append(CookieName, authResponse.Token, cookieOptions);

                // Client side — STORAGE #2: ASP.NET Core identity cookie (.AspNetCore.Cookies).
                // SignInAsync serialises the claims below into an encrypted cookie so the
                // MVC framework can hydrate User.Identity on each request without touching
                // the database or re-parsing the JWT. This powers [Authorize] attributes and
                // User.FindFirst(ClaimTypes.*) calls throughout all controllers.
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, userIdClaim),
                    new Claim(ClaimTypes.Name, usernameClaim ?? model.Username),
                    new Claim(ClaimTypes.Role, roleClaim ?? "1")
                };
                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var authProperties = new AuthenticationProperties
                {
                    IsPersistent = true,
                    ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1)
                };
                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity),
                    authProperties);

                TempData["SuccessMessage"] = $"Bem-vindo, {usernameClaim ?? model.Username}!";
                return LocalRedirect(!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl)
                    ? returnUrl
                    : "/");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Login error");
                ModelState.AddModelError(string.Empty, "Erro ao fazer login.");
                return View(model);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            if (Request.Cookies.TryGetValue(CookieName, out var token) && !string.IsNullOrWhiteSpace(token))
            {
                await _sessionService.InvalidateSessionAsync(token);
            }
            Response.Cookies.Delete(CookieName);
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        public IActionResult Register() => View();

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            var client = _httpFactory.CreateClient("Api");
            var payload = new
            {
                Name = model.Name,
                Email = model.Email,
                Username = model.Username,
                PhoneNumber = model.PhoneNumber,
                Nationality = model.Nationality,
                JobPreference = model.JobPreference,
                Profile_Bio = model.Profile_Bio,
                DoB = model.DoB,
                Role = model.Role,
                Password = model.Password
            };

            try
            {
                var resp = await client.PostAsJsonAsync("api/auth/register", payload);
                if (!resp.IsSuccessStatusCode)
                {
                    var body = await SafeReadStringAsync(resp);
                    ModelState.AddModelError("", !string.IsNullOrWhiteSpace(body) ? $"Registration failed: {body}" : $"Registration failed: {(int)resp.StatusCode} {resp.ReasonPhrase}");
                    return View(model);
                }

                return RedirectToAction("Login");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Register exception");
                ModelState.AddModelError("", "Unable to contact authentication service.");
                return View(model);
            }
        }

        // ----- Forgot Password Flow -----
        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                ModelState.AddModelError("", "O email é obrigatório.");
                return View();
            }

            var user = await _userService.FindByEmailAsync(email);
            if (user != null)
            {
                var token = _passwordResetService.GeneratePasswordResetToken(email);
                var resetUrl = Url.Action("ResetPassword", "Account", new { token }, Request.Scheme);

                await _emailSender.SendEmailAsync(
                    email,
                    "Redefinir sua senha",
                    $"Clique <a href='{resetUrl}'>aqui</a> para redefinir sua senha. Este link expira em 2 horas."
                );
            }

            // Show same message whether email is valid or not!
            ViewBag.Message = "Se este email existir, instruções de recuperação de senha foram enviadas.";
            return View();
        }

        [HttpGet]
        public IActionResult ResetPassword(string token)
        {
            if (!_passwordResetService.TryValidatePasswordResetToken(token, out var email))
            {
                return View("ResetPasswordExpired");
            }
            ViewBag.Token = token;
            ViewBag.Email = email;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(string token, string password)
        {
            if (!_passwordResetService.TryValidatePasswordResetToken(token, out var email))
            {
                return View("ResetPasswordExpired");
            }

            if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
            {
                ModelState.AddModelError("", "A senha deve ter pelo menos 8 caracteres.");
                ViewBag.Token = token;
                ViewBag.Email = email;
                return View();
            }

            try
            {
                var client = _httpFactory.CreateClient("Api");
                var payload = new
                {
                    email = email,
                    newPassword = password
                };

                var resp = await client.PostAsJsonAsync("api/auth/reset-password", payload);

                if (!resp.IsSuccessStatusCode)
                {
                    var errorBody = await SafeReadStringAsync(resp);
                    ModelState.AddModelError("", "Erro ao redefinir senha. Tente novamente.");
                    _logger.LogError($"Password reset failed: {errorBody}");
                    ViewBag.Token = token;
                    ViewBag.Email = email;
                    return View();
                }

                ViewBag.Message = "Senha redefinida com sucesso. Faça login.";
                return View("ResetPasswordSuccess");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Password reset exception");
                ModelState.AddModelError("", "Erro ao redefinir senha.");
                ViewBag.Token = token;
                ViewBag.Email = email;
                return View();
            }
        }

        // Helpers
        private static async Task<string?> SafeReadStringAsync(HttpResponseMessage resp)
        {
            try
            {
                return resp.Content == null ? null : await resp.Content.ReadAsStringAsync();
            }
            catch
            {
                return null;
            }
        }

        private class AuthResponse
        {
            public string Token { get; set; } = string.Empty;
            public DateTime ExpiresAt { get; set; }
        }
    }
}