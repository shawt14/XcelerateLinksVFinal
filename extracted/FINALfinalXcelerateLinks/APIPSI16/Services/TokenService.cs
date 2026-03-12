using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace APIPSI16.Services
{
    public interface ITokenService
    {
        string CreateToken(string subject, IEnumerable<Claim>? additionalClaims = null);
        DateTime GetLastExpiry();
    }

    // ── What is a Claim? ─────────────────────────────────────────────────────────
    //
    // A Claim is a key/value pair that asserts a fact about the authenticated user.
    // The class lives in System.Security.Claims and has two core properties:
    //   • Type  — a string that names the claim (e.g. "sub", "role", a full URI)
    //   • Value — the string value that goes with that name (e.g. "42", "Admin")
    //
    // Claims are packed into the JWT payload as JSON fields when the token is signed,
    // then unpacked by the JWT middleware on every authenticated request and made
    // available through the ClaimsPrincipal (User) object on each controller action.
    //
    // ── What is ClaimTypes? ──────────────────────────────────────────────────────
    //
    // ClaimTypes is a static class (System.Security.Claims) containing string
    // constants for the WS-* / SAML standard claim URI names, for example:
    //   ClaimTypes.NameIdentifier  → "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
    //   ClaimTypes.Name            → "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
    //   ClaimTypes.Role            → "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
    //
    // Using ClaimTypes constants instead of raw strings prevents typos and makes
    // every read-site (User.FindFirst(ClaimTypes.NameIdentifier)) consistent with
    // every write-site (new Claim(ClaimTypes.NameIdentifier, userId.ToString())).
    //
    // JwtRegisteredClaimNames (Microsoft.IdentityModel.Tokens) is a separate set of
    // short-form claim name constants defined by the JWT / IANA spec:
    //   JwtRegisteredClaimNames.Sub  → "sub"  (subject — who the token is about)
    //   JwtRegisteredClaimNames.Jti  → "jti"  (JWT ID — unique token identifier)
    //
    // The JWT middleware automatically maps the short-form "sub" claim to the
    // long-form ClaimTypes.NameIdentifier so both naming styles resolve to the same
    // ClaimsPrincipal entry after the token is validated.
    // ─────────────────────────────────────────────────────────────────────────────
    public class TokenService : ITokenService
    {
        private readonly IConfiguration _config;
        private DateTime _lastExpiry = DateTime.UtcNow;

        public TokenService(IConfiguration config)
        {
            _config = config;
        }

        // CreateToken — packs claims into a signed JWT string.
        //
        // 'subject' is the user's primary key (UserId) as a string.
        // 'additionalClaims' are the application-level claims defined by the caller
        // (AuthController.Login), such as ClaimTypes.Name, ClaimTypes.Role, etc.
        // Both sets are merged into the JWT payload before signing.
        public string CreateToken(string subject, IEnumerable<Claim>? additionalClaims = null)
        {
            // Read key from env var first then config
            var keyBase64 = Environment.GetEnvironmentVariable("XCELERATE_JWT_KEY")
                            ?? _config["Jwt:Key"];

            if (string.IsNullOrWhiteSpace(keyBase64))
                throw new InvalidOperationException("JWT key not configured. Set XCELERATE_JWT_KEY or Jwt:Key.");

            byte[] keyBytes;
            try
            {
                keyBytes = Convert.FromBase64String(keyBase64);
            }
            catch (FormatException fx)
            {
                throw new InvalidOperationException("JWT key is not valid base64. Check XCELERATE_JWT_KEY or Jwt:Key value.", fx);
            }

            var issuer = _config["Jwt:Issuer"] ?? "xcelerate-links-api";
            var audience = _config["Jwt:Audience"] ?? "xcelerate-links-clients";

            
            var expireRaw = _config["Jwt:ExpireMinutes"];
            int expireMinutes;
            if (!int.TryParse(expireRaw, out expireMinutes) || expireMinutes <= 0)
            {
                expireMinutes = 60;
            }

            var claims = new List<Claim>
            {
                // "sub" (subject) — identifies who the token is about. JWT middleware
                // maps this short-form name to ClaimTypes.NameIdentifier so callers can
                // use either User.FindFirst("sub") or User.FindFirst(ClaimTypes.NameIdentifier).
                new Claim(JwtRegisteredClaimNames.Sub, subject),

                // "jti" (JWT ID) — a unique identifier for this specific token instance.
                // Useful for token revocation lists and preventing replay attacks.
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            if (additionalClaims != null)
                claims.AddRange(additionalClaims);

            var creds = new SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256);
            var expires = DateTime.UtcNow.AddMinutes(expireMinutes);
            _lastExpiry = expires;

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public DateTime GetLastExpiry() => _lastExpiry;
    }
}