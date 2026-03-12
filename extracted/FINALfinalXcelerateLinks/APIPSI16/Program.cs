using APIPSI16.Data;
using APIPSI16.Models;
using APIPSI16.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System;

var builder = WebApplication.CreateBuilder(args);

// ---- Kestrel URLs ----
var defaultUrls = "https://localhost:7263;http://localhost:5270";
var urls = Environment.GetEnvironmentVariable("ASPNETCORE_URLS") ?? defaultUrls;
builder.WebHost.UseUrls(urls);

// ---- CORS policy ----
var corsOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? Array.Empty<string>();
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowMvcFrontend", policy =>
    {
        if (corsOrigins.Length > 0)
        {
            policy.WithOrigins(corsOrigins)
                  .AllowAnyHeader()
                  .AllowAnyMethod()
                  .AllowCredentials();
        }
        else
        {
            policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod();
        }
    });
});

// ---- Connection string ----
var defaultConn = Environment.GetEnvironmentVariable("ConnectionStrings__DefaultConnection")
                  ?? builder.Configuration.GetConnectionString("DefaultConnection");

if (string.IsNullOrWhiteSpace(defaultConn))
{
    throw new InvalidOperationException("ConnectionStrings:DefaultConnection not configured.");
}

// ---- Register DbContext (scoped) ----
// IMPORTANT: force EF Core to use migrations from THIS project/assembly.
// This prevents EF from accidentally picking up a different migrations assembly.
builder.Services.AddDbContext<xcleratesystemslinks_SampleDBContext>(options =>
{
    options.UseSqlServer(defaultConn, sql =>
    {
        sql.MigrationsAssembly(typeof(Program).Assembly.FullName);
        // Optional: increase command timeout during migration
        // sql.CommandTimeout(120);
    });
});

// ---- Controllers & Swagger ----
builder.Services.AddControllers()
    .AddJsonOptions(opts =>
        opts.JsonSerializerOptions.ReferenceHandler =
            System.Text.Json.Serialization.ReferenceHandler.IgnoreCycles);

builder.Services.AddSignalR();
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "APIPSI16 API", Version = "v1" });

    c.MapType<IFormFile>(() => new OpenApiSchema
    {
        Type = "string",
        Format = "binary"
    });

    c.OperationFilter<APIPSI16.Filters.FileUploadOperation>();

    var securityScheme = new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter your JWT token in the format: Bearer {token}"
    };

    c.AddSecurityDefinition("Bearer", securityScheme);

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// ---- JWT Configuration ----
var keyBase64 = Environment.GetEnvironmentVariable("XCELERATE_JWT_KEY")
               ?? builder.Configuration["Jwt:Key"];

if (string.IsNullOrWhiteSpace(keyBase64))
{
    throw new InvalidOperationException("JWT key not configured. Set XCELERATE_JWT_KEY environment variable or Jwt:Key in appsettings.");
}

byte[] keyBytes;
try
{
    keyBytes = Convert.FromBase64String(keyBase64);
}
catch (FormatException)
{
    throw new InvalidOperationException("JWT key is not valid base64. Check XCELERATE_JWT_KEY or Jwt:Key value.");
}

var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "xcelerate-links-api";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "xcelerate-links-clients";

// ---- Register services ----
builder.Services.AddSingleton<ITokenService, TokenService>();
builder.Services.AddScoped<IPasswordHasher<User>, PasswordHasher<User>>();
builder.Services.AddScoped<IFileStorageService, FileStorageService>();
builder.Services.AddScoped<ISessionService, SessionService>();

// ---- Authentication (JWT Bearer) ----
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = builder.Environment.IsProduction();
    options.SaveToken = true;

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(keyBytes),

        ValidateIssuer = true,
        ValidIssuer = jwtIssuer,

        ValidateAudience = true,
        ValidAudience = jwtAudience,

        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromSeconds(30)
    };

    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = ctx =>
        {
            var logger = ctx.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            var authHeader = ctx.Request.Headers["Authorization"].FirstOrDefault();
            if (!string.IsNullOrEmpty(authHeader))
            {
                logger.LogDebug("JWT OnMessageReceived. Authorization header present: {HasBearer}", authHeader.StartsWith("Bearer "));
            }
            return Task.CompletedTask;
        },
        OnTokenValidated = ctx =>
        {
            var logger = ctx.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            var userId = ctx.Principal?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            var userName = ctx.Principal?.FindFirst(System.Security.Claims.ClaimTypes.Name)?.Value;
            var userRole = ctx.Principal?.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value;
            logger.LogInformation("JWT validated. User: {UserName} (ID: {UserId}), Role: {Role}", userName, userId, userRole ?? "NONE");
            return Task.CompletedTask;
        },
        OnAuthenticationFailed = ctx =>
        {
            var logger = ctx.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogError(ctx.Exception, "JWT authentication failed: {Message}", ctx.Exception.Message);
            return Task.CompletedTask;
        },
        OnChallenge = ctx =>
        {
            var logger = ctx.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogWarning("JWT challenge triggered. Error: {Error}, Description: {Description}", ctx.Error ?? "none", ctx.ErrorDescription ?? "none");
            return Task.CompletedTask;
        }
    };
});

builder.Services.AddAuthorization();

// ---- Build the app ----
var app = builder.Build();

// ---- Startup diagnostics ----
using (var scope = app.Services.CreateScope())
{
    var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

    try
    {
        logger.LogInformation("=== JWT Configuration ===");
        logger.LogInformation("Key source: {Source}",
            Environment.GetEnvironmentVariable("XCELERATE_JWT_KEY") != null ? "Environment variable" : "appsettings.json");
        logger.LogInformation("Key length: {Length} bytes", keyBytes.Length);
        logger.LogInformation("Issuer: {Issuer}", jwtIssuer);
        logger.LogInformation("Audience: {Audience}", jwtAudience);

        logger.LogInformation("=== CORS Configuration ===");
        if (corsOrigins.Length > 0)
        {
            logger.LogInformation("Allowed origins: {Origins}", string.Join(", ", corsOrigins));
        }
        else
        {
            logger.LogInformation("CORS: Allow all origins (development mode)");
        }

        logger.LogInformation("=== Database Configuration ===");
        logger.LogInformation("Connection source: {Source}",
            Environment.GetEnvironmentVariable("ConnectionStrings__DefaultConnection") != null ? "Environment variable" : "appsettings.json");

        var ctx = scope.ServiceProvider.GetRequiredService<xcleratesystemslinks_SampleDBContext>();
        _ = ctx.Model;
        logger.LogInformation("DbContext resolved successfully.");

        // Log migrations state so you can see exactly what EF thinks it should do.
        var applied = ctx.Database.GetAppliedMigrations().ToList();
        var pending = ctx.Database.GetPendingMigrations().ToList();
        logger.LogInformation("EF migrations applied: {Count}", applied.Count);
        logger.LogInformation("EF migrations pending: {Count}", pending.Count);
        if (pending.Count > 0)
        {
            logger.LogWarning("Pending migrations: {Pending}", string.Join(", ", pending));
        }

        // Apply pending migrations automatically at startup.
        // NOTE: If your DB was created manually / has drift, this can throw.
        // Keep this enabled only if you want EF to manage schema.
        try
        {
            // If you want to avoid the Companies conflict while debugging, comment this out temporarily.
            ctx.Database.Migrate();

            logger.LogInformation("Database migrations applied successfully.");
        }
        catch (Exception migEx)
        {
            logger.LogError(migEx, "Failed to apply database migrations. The application will continue but may have schema issues.");
        }

        // Safety-net: ensure IsDiscarded and PriorityId columns exist on EmployerCandidateHistory.
        // This is needed because most migrations in this project are missing the [Migration] attribute
        // and were applied manually, so __EFMigrationsHistory may not reflect their state. The raw
        // SQL check below is idempotent and guarantees the columns exist regardless of EF history.
        // TODO: Remove this block once the migration history is fully in sync (all migrations have
        //       the [Migration] attribute and __EFMigrationsHistory is up to date).
        try
        {
            var conn = ctx.Database.GetDbConnection();
            if (conn.State != System.Data.ConnectionState.Open)
                conn.Open();

            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
IF NOT EXISTS (
    SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_NAME = 'EmployerCandidateHistory' AND COLUMN_NAME = 'IsDiscarded'
)
    ALTER TABLE EmployerCandidateHistory ADD IsDiscarded bit NOT NULL DEFAULT 0;

IF NOT EXISTS (
    SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_NAME = 'EmployerCandidateHistory' AND COLUMN_NAME = 'PriorityId'
)
    ALTER TABLE EmployerCandidateHistory ADD PriorityId int NULL;
";
            cmd.ExecuteNonQuery();
            logger.LogInformation("EmployerCandidateHistory schema columns verified/applied.");
        }
        catch (Exception schemaEx)
        {
            logger.LogError(schemaEx, "Failed to verify/apply EmployerCandidateHistory schema columns.");
        }

        logger.LogInformation("=== Startup complete ===");
    }
    catch (Exception ex)
    {
        logger.LogCritical(ex, "Startup validation failed.");
        throw;
    }
}

// ── Middleware pipeline (API — APIPSI16) ─────────────────────────────────────
//
// ASP.NET Core processes every HTTP request through an ordered chain of middleware
// components. The ORDER in which you call app.Use*() matters: each middleware
// wraps all middleware registered after it. Think of it as nested Russian dolls —
// the first registered runs first on the way IN and last on the way OUT.
//
// The pipeline for this API:
//
//   Request ──►
//     [1] UseDeveloperExceptionPage / UseSwagger  (Development only)
//     [2] UseHttpsRedirection
//     [3] UseStaticFiles
//     [4] UseCors
//     [5] UseAuthentication
//     [6] UseAuthorization
//     [7] MapControllers / MapHub   ◄── actual endpoint handlers
//   ◄── Response
//
// ─────────────────────────────────────────────────────────────────────────────
if (app.Environment.IsDevelopment())
{
    // [1a] UseDeveloperExceptionPage — catches unhandled exceptions thrown anywhere
    //      further down the pipeline and returns a full HTML stack trace to the
    //      browser. Only active in Development; production uses a generic error page.
    app.UseDeveloperExceptionPage();

    // [1b] UseSwagger / UseSwaggerUI — mounts the OpenAPI JSON document at
    //      /swagger/v1/swagger.json and the Swagger interactive UI at /swagger.
    //      Swagger lets you test API endpoints directly in the browser without a
    //      separate client. Only available in Development to avoid exposing the
    //      API surface in production.
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "APIPSI16 API v1");
        c.DocumentTitle = "APIPSI16 - Swagger";
    });
}

// [2] UseHttpsRedirection — if the client sends a plain HTTP request, this
//     middleware redirects it to the equivalent HTTPS URL (301/307 redirect).
//     Ensures all traffic is encrypted in transit. Must come early, before any
//     middleware that reads request data, so the redirect happens before any
//     sensitive data is processed over an unencrypted connection.
app.UseHttpsRedirection();

// [3] UseStaticFiles — serves files from the wwwroot folder (CSS, JS, images)
//     directly without hitting any controller. Short-circuits the pipeline for
//     matching paths so no auth check is applied to static assets.
app.UseStaticFiles();

// [4] UseCors — applies the "AllowMvcFrontend" CORS policy defined above.
//     CORS (Cross-Origin Resource Sharing) controls which origins (domains) are
//     allowed to call this API from a browser. Must come BEFORE UseAuthentication
//     so that OPTIONS preflight requests are handled before auth middleware runs.
//     Without this, browsers making cross-origin requests to this API would be
//     blocked by the browser's same-origin policy.
app.UseCors("AllowMvcFrontend");

// [5] UseAuthentication — reads the Authorization: Bearer <JWT> header and
//     validates the token signature, issuer, audience, and expiry using the
//     TokenValidationParameters configured above. On success it populates
//     HttpContext.User (the ClaimsPrincipal) with the claims from the token.
//     MUST come before UseAuthorization so that User is populated before
//     the authorization policy is evaluated.
app.UseAuthentication();

// [6] UseAuthorization — evaluates [Authorize] attributes on controllers and
//     actions. Uses the ClaimsPrincipal populated by UseAuthentication to decide
//     whether the current user has access to the requested resource.
//     Returns 401 Unauthorized if the user is not authenticated, or 403 Forbidden
//     if authenticated but not authorized (wrong role).
app.UseAuthorization();

// NOTE: SessionValidationMiddleware is currently NOT registered globally here.
// Session cross-checking against the Sessions DB table is instead done explicitly
// in each controller via ApiControllerBase.ValidateSessionAsync(). The class
// still exists in /Middleware/SessionValidationMiddleware.cs and can be re-enabled
// with app.UseMiddleware<SessionValidationMiddleware>() if global enforcement is
// preferred. If re-enabled, it must be placed AFTER UseAuthentication (line [5]).

// [7a] MapControllers — registers all [ApiController]-decorated controllers as
//      routable endpoints. This is the terminal middleware: it matches the request
//      URL to a controller action, executes it, and writes the response.
app.MapControllers();

// [7b] MapHub — registers the SignalR ChatHub at the /hubs/chat WebSocket endpoint.
//      SignalR uses a persistent WebSocket connection (with HTTP long-polling as
//      a fallback) to push real-time messages from the server to connected clients.
//      The hub endpoint is handled after all other middleware so authentication
//      and authorization are enforced on the WebSocket upgrade handshake as well.
app.MapHub<APIPSI16.Hubs.ChatHub>("/hubs/chat");
// ─────────────────────────────────────────────────────────────────────────────

app.Logger.LogInformation("API is running. Listening on: {Urls}", urls);

app.Run();