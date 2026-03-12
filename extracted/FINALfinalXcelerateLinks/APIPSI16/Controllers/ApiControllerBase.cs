using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using APIPSI16.Services;

namespace APIPSI16.Controllers
{
    // ApiControllerBase (API layer) — shared session guard for all API controllers.
    //
    // After the JWT middleware validates the token signature, it deserialises the
    // embedded claims and makes them available through the ClaimsPrincipal (User)
    // property on every ControllerBase. This class provides ValidateSessionAsync()
    // which reads those claims to cross-check the token against the Sessions table.
    public class ApiControllerBase : ControllerBase
    {
        protected readonly ISessionService _sessionService;

        public ApiControllerBase(ISessionService sessionService)
        {
            _sessionService = sessionService;
        }

        protected async Task<IActionResult> ValidateSessionAsync()
        {
            if (_sessionService == null)
                return Unauthorized(new { error = "Session validation unavailable." });

            if (User.Identity?.IsAuthenticated != true)
                return Unauthorized(new { error = "Not authenticated." });

            // ClaimTypes.NameIdentifier holds the user's primary key (UserId).
            // It was embedded as a claim in the JWT during login (AuthController)
            // and is now deserialized here by the JWT middleware into User.Claims.
            // FindFirst returns the FIRST matching Claim object; .Value gives the string.
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrWhiteSpace(userIdClaim) || !int.TryParse(userIdClaim, out var userId))
                return Unauthorized(new { error = "Invalid user claim." });

            // Get the token from the Authorization header
            var authHeader = Request.Headers["Authorization"].ToString();
            if (string.IsNullOrWhiteSpace(authHeader) || !authHeader.StartsWith("Bearer "))
                return Unauthorized(new { error = "No token provided." });

            var token = authHeader.Substring("Bearer ".Length).Trim();

            bool isValidSession = await _sessionService.IsSessionValidAsync(userId, token);

            if (!isValidSession)
            {
                return Unauthorized(new { error = "Session has been invalidated. Please log in again." });
            }

            return null; // Session is valid
        }
    }
}