using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using APIPSI16.Data;
using APIPSI16.Services;

namespace APIPSI16.Middleware
{
    // ── SessionValidationMiddleware ───────────────────────────────────────────────
    //
    // PURPOSE
    // -------
    // This is a custom ASP.NET Core middleware component. Its job is to enforce
    // server-side session validity on every API request — on top of the standard
    // JWT signature/expiry check that is already done by UseAuthentication().
    //
    // WHY IT EXISTS
    // -------------
    // A signed JWT is valid until its expiry time ("exp" claim) elapses. There is
    // no built-in mechanism to revoke a JWT early (e.g., on logout or password change).
    // This middleware closes that gap by cross-checking every authenticated request
    // against the Sessions table in the database:
    //   • If no matching session exists → 401 (token was never stored / already deleted)
    //   • If the session row has IsActive = false → 401 (explicitly logged out or
    //     invalidated because a new login was started from another device)
    //   • If the session row has expired (ExpiresAt < now) → mark inactive, return 401
    //
    // PIPELINE POSITION
    // -----------------
    // This middleware MUST be registered AFTER UseAuthentication() so that the JWT
    // bearer middleware has already run and Context.User is populated with claims
    // before this code reads ClaimTypes.NameIdentifier.
    //
    // CURRENT STATUS
    // --------------
    // The registration line in Program.cs is currently commented out
    // (// REMOVE: app.UseMiddleware<SessionValidationMiddleware>();).
    // Session validation is instead performed per-controller inside
    // ApiControllerBase.ValidateSessionAsync(), which is called explicitly at the
    // top of each protected action. The middleware approach would enforce it globally
    // without needing per-controller calls but requires more careful bypass-path
    // management (auth endpoints, SignalR handshake, health checks, etc.).
    //
    // HOW MIDDLEWARE WORKS IN ASP.NET CORE
    // -------------------------------------
    // The ASP.NET Core request pipeline is a chain of middleware components. Each
    // component receives an HttpContext and a RequestDelegate (_next) pointing to the
    // next component in the chain.
    //
    //   Browser ──► [UseHttpsRedirection] ──► [UseCors] ──► [UseAuthentication]
    //           ──► [UseAuthorization] ──► [SessionValidationMiddleware] ──► Controller
    //
    // A middleware can:
    //   a) Call await _next(context) to continue the chain (request flows forward).
    //   b) Write a response and return WITHOUT calling _next (short-circuit / stop).
    //
    // This middleware short-circuits (case b) whenever the session is invalid,
    // writing a 401 JSON response and stopping further processing.
    // ─────────────────────────────────────────────────────────────────────────────
    public class SessionValidationMiddleware
    {
        private readonly RequestDelegate _next;

        public SessionValidationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, ISessionService sessionService, xcleratesystemslinks_SampleDBContext db)
        {
            var path = context.Request.Path.Value ?? "";
            // Auth endpoints are excluded from session validation because the session
            // does not exist yet (login) or has already been removed (logout).
            if (path.Contains("/api/auth/login") || path.Contains("/api/auth/register") || path.Contains("/api/auth/login-debug"))
            {
                await _next(context);
                return;
            }

            // ClaimTypes.NameIdentifier is read from the HttpContext.User ClaimsPrincipal.
            // By the time this middleware runs, the JWT bearer middleware has already
            // validated the token signature and deserialized all embedded claims into
            // context.User.Claims. FindFirst searches that collection for the claim whose
            // Type property equals ClaimTypes.NameIdentifier (the long-form URI string),
            // which corresponds to the "sub" (subject) field in the JWT payload.
            // The resulting .Value is the UserId string embedded at login.
            var userIdClaim = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var token = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");

            if (!string.IsNullOrWhiteSpace(userIdClaim) && !string.IsNullOrWhiteSpace(token) && int.TryParse(userIdClaim, out var userId))
            {
                var session = await db.Sessions
                    .FirstOrDefaultAsync(s => s.Token == token && s.UserId == userId);

                if (session == null)
                {
                    // Just return 401 - don't try to sign out
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "Session not found" });
                    return;
                }

                if (!session.IsActive)
                {
                    // Just return 401 - don't try to sign out
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "Session has been invalidated. Please log in again." });
                    return;
                }

                if (session.ExpiresAt < DateTime.UtcNow)
                {
                    session.IsActive = false;
                    session.InvalidatedAt = DateTime.UtcNow;
                    db.Sessions.Update(session);
                    await db.SaveChangesAsync();

                    // Just return 401 - don't try to sign out
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "Session expired" });
                    return;
                }
            }

            await _next(context);
        }
    }
}