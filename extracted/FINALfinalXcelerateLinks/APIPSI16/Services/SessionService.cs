using System;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using APIPSI16.Data;
using APIPSI16.Models;

namespace APIPSI16.Services
{
    public interface ISessionService
    {
        Task<Session> CreateSessionAsync(int userId, string token, DateTime expiresAt);
        Task InvalidateAllUserSessionsAsync(int userId);
        Task<bool> IsSessionValidAsync(int userId, string token);
        Task InvalidateSessionAsync(string token);
    }

    // SessionService — the server-side token store.
    //
    // Every JWT that is issued to a user is also written to the Sessions table in the
    // SQL database. This is the second place (alongside the browser cookie) where the
    // token is "saved". Storing it server-side gives the application the ability to:
    //   • Revoke a token immediately on logout without waiting for it to expire.
    //   • Enforce a single-active-session-per-user policy (only one login at a time).
    //   • Detect token theft: if a cookie arrives whose token is not in the Sessions
    //     table (or is marked inactive), the request is rejected even if the JWT
    //     signature is mathematically valid.
    //
    // The Sessions table schema (see Session.cs / AddSessionsTable migration):
    //   UserId      – foreign key to Users
    //   Token       – the raw JWT string (full, not hashed)
    //   CreatedAt   – when the session was created
    //   ExpiresAt   – when it should be treated as expired
    //   IsActive    – true until logout or a new login invalidates it
    //   InvalidatedAt – set when IsActive is flipped to false
    public class SessionService : ISessionService
    {
        private readonly xcleratesystemslinks_SampleDBContext _db;

        public SessionService(xcleratesystemslinks_SampleDBContext db)
        {
            _db = db ?? throw new ArgumentNullException(nameof(db));
        }

        // CreateSessionAsync — persists the new JWT to the Sessions table.
        // Called by AuthController.Login immediately after the token is generated.
        // Before inserting, it invalidates every existing active session for the user
        // so that only one session can be active at a time (single-device policy).
        public async Task<Session> CreateSessionAsync(int userId, string token, DateTime expiresAt)
        {
            // FIRST: Invalidate ALL old sessions for this user
            var oldSessions = await _db.Sessions
                .Where(s => s.UserId == userId && s.IsActive)
                .ToListAsync();

            foreach (var oldSession in oldSessions)
            {
                oldSession.IsActive = false;
                oldSession.InvalidatedAt = DateTime.UtcNow;
            }

            if (oldSessions.Any())
            {
                await _db.SaveChangesAsync();
            }

            // THEN: Create the new session record. The full JWT string is stored in
            // Token so it can be compared against the cookie value on each request.
            var session = new Session
            {
                UserId = userId,
                Token = token,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = expiresAt,
                IsActive = true,
                InvalidatedAt = null
            };

            _db.Sessions.Add(session);
            await _db.SaveChangesAsync();

            return session;
        }

        // InvalidateAllUserSessionsAsync — marks every active session for a user as
        // inactive. Called before creating a new session so the old cookie (if still in
        // the user's browser from another device) becomes immediately unusable.
        public async Task InvalidateAllUserSessionsAsync(int userId)
        {
            var activeSessions = await _db.Sessions
                .Where(s => s.UserId == userId && s.IsActive)
                .ToListAsync();

            foreach (var session in activeSessions)
            {
                session.IsActive = false;
                session.InvalidatedAt = DateTime.UtcNow;
            }

            if (activeSessions.Any())
            {
                await _db.SaveChangesAsync();
            }
        }

        // IsSessionValidAsync — the gatekeeper called on every authenticated MVC request
        // (via BaseController.ValidateSessionAsync). Looks up the Sessions table for a
        // record that matches both the userId and the exact token string from the cookie,
        // and confirms the session is still marked active and not yet expired.
        // Returning false causes BaseController to delete the cookie and sign the user out.
        public async Task<bool> IsSessionValidAsync(int userId, string token)
        {
            var session = await _db.Sessions
                .FirstOrDefaultAsync(s =>
                    s.UserId == userId &&
                    s.Token == token &&
                    s.IsActive &&
                    s.ExpiresAt > DateTime.UtcNow);

            return session != null;
        }

        // InvalidateSessionAsync — called on explicit logout. Marks the specific token
        // (identified by its JWT string) as inactive so it cannot be reused even if the
        // cookie somehow persists in the browser after logout.
        public async Task InvalidateSessionAsync(string token)
        {
            var session = await _db.Sessions
                .FirstOrDefaultAsync(s => s.Token == token && s.IsActive);

            if (session != null)
            {
                session.IsActive = false;
                session.InvalidatedAt = DateTime.UtcNow;
                await _db.SaveChangesAsync();
            }
        }
    }
}