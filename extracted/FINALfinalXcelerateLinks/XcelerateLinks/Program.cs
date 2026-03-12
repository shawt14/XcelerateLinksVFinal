using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication.Cookies;
using XcelerateLinks.Mvc.Services;             // TokenHandler, ApiClient, IApiClient, UsersApiClient
using XcelerateLinks.Models.ViewModels;
using XcelerateLinks.Mvc.Http;
using APIPSI16.Data;
using Microsoft.EntityFrameworkCore;
using APIPSI16.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Logging.AddConsole();
builder.Services.AddControllersWithViews();
builder.Services.AddHttpContextAccessor();
builder.Services.AddTransient<TokenHandler>();

var mvcConnStr = Environment.GetEnvironmentVariable("ConnectionStrings__DefaultConnection")
    ?? builder.Configuration.GetConnectionString("DefaultConnection")
    ?? "Server=sql.bsite.net\\MSSQL2016;Database=xcleratesystemslinks_SampleDB;User Id=xcleratesystemslinks_SampleDB;Password=XcelerateDB;Encrypt=True;TrustServerCertificate=True;MultipleActiveResultSets=True;";

builder.Services.AddDbContext<xcleratesystemslinks_SampleDBContext>(options =>
    options.UseSqlServer(mvcConnStr));

builder.Services.AddScoped<ISessionService, SessionService>();

// ---- Add services for password reset ----
builder.Services.AddSingleton<PasswordResetService>();
builder.Services.AddSingleton<IEmailSender, EmailSender>();
builder.Services.AddScoped<IUserService, UserService>();
// ----------------------------------------

var apiBase = Environment.GetEnvironmentVariable("Api__BaseUrl")
              ?? builder.Configuration["Api:BaseUrl"]
              ?? throw new InvalidOperationException("Api:BaseUrl not configured in appsettings.json or environment variable Api__BaseUrl.");

builder.Logging.AddConsole();
Console.WriteLine($"[MVC] Api BaseUrl = {apiBase}");

if (!apiBase.EndsWith('/')) apiBase += '/';

HttpMessageHandler CreatePrimaryHandler()
{
    if (builder.Environment.IsDevelopment())
    {
        return new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };
    }
    return new HttpClientHandler();
}

builder.Services.AddTransient<LoggingHandler>();

// Register named HttpClient "Api" with TokenHandler
builder.Services.AddHttpClient("Api", client =>
{
    client.BaseAddress = new Uri(apiBase);
    client.DefaultRequestHeaders.Accept.Clear();
    client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
})
.AddHttpMessageHandler<TokenHandler>()
.ConfigurePrimaryHttpMessageHandler(CreatePrimaryHandler);

// Register typed API client for generic calls
builder.Services.AddHttpClient<IApiClient, ApiClient>(client =>
{
    client.BaseAddress = new Uri(apiBase);
    client.DefaultRequestHeaders.Accept.Clear();
    client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
})
.AddHttpMessageHandler<TokenHandler>()
.ConfigurePrimaryHttpMessageHandler(CreatePrimaryHandler);

// Register UsersApiClient as scoped (correct for your constructor!)
builder.Services.AddScoped<IUsersApiClient, UsersApiClient>();

// Cookie authentication for MVC site
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
        options.Cookie.Name = ".AspNetCore.Authentication.Cookies";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
            ? CookieSecurePolicy.SameAsRequest
            : CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.ExpireTimeSpan = TimeSpan.FromHours(1);
        options.SlidingExpiration = true;
    });

builder.Services.AddScoped<IFileStorageService, FileStorageService>();

var app = builder.Build();

// ── Middleware pipeline (MVC — XcelerateLinks) ───────────────────────────────
//
// ASP.NET Core processes every HTTP request through an ordered chain of middleware.
// Each app.Use*() call adds one link to that chain. The order is critical:
// each middleware can only see/modify context state set by middleware registered
// BEFORE it. The pipeline for this MVC site:
//
//   Request ──►
//     [1] UseExceptionHandler / UseHsts   (Production only)
//     [2] UseHttpsRedirection
//     [3] UseStaticFiles
//     [4] UseRouting
//     [5] UseAuthentication
//     [6] UseAuthorization
//     [7] MapControllerRoute              ◄── MVC controller/view handlers
//   ◄── Response
//
// ─────────────────────────────────────────────────────────────────────────────
if (!app.Environment.IsDevelopment())
{
    // [1a] UseExceptionHandler — in Production, catches unhandled exceptions and
    //      redirects to /Home/Error so the user sees a friendly error page instead
    //      of a raw stack trace. In Development this is replaced by
    //      UseDeveloperExceptionPage (implicitly added by CreateBuilder in dev).
    app.UseExceptionHandler("/Home/Error");

    // [1b] UseHsts — sends the HTTP Strict-Transport-Security (HSTS) response header
    //      which tells browsers to only ever connect via HTTPS for the next N days.
    //      Only enabled in Production because localhost development uses plain HTTP.
    app.UseHsts();
}

// [2] UseHttpsRedirection — redirects plain HTTP requests to HTTPS.
//     Ensures all communication with the MVC site is encrypted.
app.UseHttpsRedirection();

// [3] UseStaticFiles — serves CSS, JavaScript, images, and other files from
//     the wwwroot folder directly, short-circuiting the pipeline.
//     No authentication is required to access static assets.
app.UseStaticFiles();

// [4] UseRouting — analyses the incoming request URL and selects the matching
//     endpoint (controller action). MUST come before UseAuthentication so the
//     route is resolved before auth decisions are made.
app.UseRouting();

// [5] UseAuthentication — reads the encrypted ASP.NET Core cookie
//     (.AspNetCore.Authentication.Cookies) that was set by AccountController.Login,
//     decrypts it, and populates HttpContext.User with the stored Claims
//     (NameIdentifier, Name, Role). MUST come after UseRouting and before
//     UseAuthorization so that User is populated when authorization runs.
//     Note: this is Cookie authentication (not JWT). The MVC site stores the
//     user's identity in a server-encrypted cookie; the raw JWT is stored
//     separately in the ApiAccessToken cookie and forwarded to the API by
//     TokenHandler on every outbound HttpClient call.
app.UseAuthentication();

// [6] UseAuthorization — evaluates [Authorize] attributes on MVC controllers and
//     actions using the ClaimsPrincipal populated in step [5].
//     Unauthenticated users are redirected to /Account/Login (configured above
//     in AddCookie → options.LoginPath).
app.UseAuthorization();

// [7] MapControllerRoute — registers the conventional MVC route pattern so that
//     URLs like /Home/Index or /Account/Login map to the correct controller/action.
//     This is the terminal middleware: it executes the controller and renders the
//     Razor view response.
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
// ─────────────────────────────────────────────────────────────────────────────

Console.WriteLine($"[MVC] Api BaseUrl = {apiBase}");

app.Run();