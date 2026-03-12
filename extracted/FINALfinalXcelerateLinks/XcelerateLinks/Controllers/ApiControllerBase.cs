using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using XcelerateLinks.Mvc.Services;
using APIPSI16.Services;

namespace XcelerateLinks.Mvc.Controllers
{
    [Authorize]
    public abstract class ApiControllerBase : BaseController
    {
        private readonly IHttpClientFactory _httpFactory;

        protected ApiControllerBase(IHttpClientFactory httpFactory, ISessionService sessionService)
            : base(sessionService)  // Pass to base
        {
            _httpFactory = httpFactory;
        }

        protected HttpClient CreateAuthorizedClient()
        {
            var client = _httpFactory.CreateClient("Api");
            if (Request.Cookies.TryGetValue(TokenHandler.CookieName, out var token) && !string.IsNullOrWhiteSpace(token))
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }

            return client;
        }

        // GetCurrentUserId — convenience helper that reads the ClaimTypes.NameIdentifier
        // claim from the ASP.NET Core identity cookie (set by AccountController.Login via
        // SignInAsync). The raw value is a string (the UserId stored as text in the claim);
        // int.TryParse converts it to the numeric type used by the database layer.
        // Returns null if the claim is missing or cannot be parsed as an integer.
        protected int? GetCurrentUserId()
        {
            var claim = User.FindFirst(ClaimTypes.NameIdentifier);
            return claim != null && int.TryParse(claim.Value, out var id) ? id : null;
        }

        // IsAdmin — reads the ClaimTypes.Role claim and checks whether its value is "0".
        // Role values are defined in AuthController:
        //   "0" = Admin, "1" = Regular user, "2" = Employer.
        // The role was embedded in the JWT at login and copied to the identity cookie
        // claims by AccountController, so it is available here without a DB round-trip.
        protected bool IsAdmin() => User.FindFirst(ClaimTypes.Role)?.Value == "0";

        protected static async Task<string?> SafeReadStringAsync(HttpResponseMessage resp)
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
    }
}