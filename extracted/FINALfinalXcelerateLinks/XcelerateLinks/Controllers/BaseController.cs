using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using APIPSI16.Services;

namespace XcelerateLinks.Mvc.Controllers
{
    // BaseController — shared session validation and token cookie management.
    //
    // All authenticated controllers in this MVC app inherit from ApiControllerBase
    // which itself inherits from BaseController. This gives every action access to
    // ValidateSessionAsync(), which cross-checks the token stored in the browser
    // cookie against the server-side Sessions table on each request. If the server
    // has revoked the session (e.g. because the user logged in on another device),
    // the browser cookie is deleted here and the user is signed out immediately.
    public abstract class BaseController : Controller
    {
        protected readonly ISessionService _sessionService;

        // CookieName must match the constant in TokenHandler and AccountController.
        // The actual JWT is stored in this cookie (set during login, deleted on logout).
        protected const string CookieName = "ApiAccessToken";

        public BaseController(ISessionService sessionService = null)
        {
            _sessionService = sessionService;
        }

        // ValidateSessionAsync — called at the top of sensitive controller actions.
        //
        // Flow:
        //   1. Read the JWT string from the "ApiAccessToken" cookie.
        //   2. Ask SessionService.IsSessionValidAsync() to check the Sessions table:
        //      — Does a record exist for (userId, token)?
        //      — Is IsActive = true?
        //      — Is ExpiresAt still in the future?
        //   3. If the session is invalid:
        //      — Delete the "ApiAccessToken" cookie from the browser.
        //      — Sign out the ASP.NET Core identity cookie (.AspNetCore.Cookies).
        //      — Return false so the controller can redirect to the login page.
        protected async Task<bool> ValidateSessionAsync()
        {
            if (_sessionService == null)
                return true; // No session service injected

            if (User.Identity?.IsAuthenticated != true)
                return true;

            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (!Request.Cookies.TryGetValue(CookieName, out var token) ||
                string.IsNullOrWhiteSpace(userIdClaim) ||
                !int.TryParse(userIdClaim, out var userId))
            {
                return true;
            }

            bool isValidSession = await _sessionService.IsSessionValidAsync(userId, token);

            if (!isValidSession)
            {
                // Token is no longer valid server-side — remove both cookies so the
                // browser is fully signed out. The raw JWT cookie is deleted here;
                // the ASP.NET Core identity cookie is cleared by SignOutAsync.
                Response.Cookies.Delete(CookieName);
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                TempData["ErrorMessage"] = "Sua sess�o foi encerrada. Por favor, fa�a login novamente.";
                return false;
            }

            return true;
        }
    }
}