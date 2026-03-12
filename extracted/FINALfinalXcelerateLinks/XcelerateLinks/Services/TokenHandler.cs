using System.Net.Http;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Http;

namespace XcelerateLinks.Mvc.Services
{
    // TokenHandler — the bridge between the browser cookie and the REST API.
    //
    // Every outbound HTTP call made through the "Api" named HttpClient passes through
    // this delegating handler. It reads the raw JWT from the HttpOnly browser cookie
    // named "ApiAccessToken" and attaches it as an Authorization: Bearer header on the
    // outgoing request so the API can authenticate the call.
    //
    // This means the raw token never needs to be touched by any controller or service;
    // the handler intercepts at the HttpClient pipeline level transparently.
    public class TokenHandler : DelegatingHandler
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        // CookieName must match the cookie written by AccountController.Login.
        // Centralising it here as a public constant lets other classes (BaseController,
        // AccountController) reference it without duplicating the string literal.
        public const string CookieName = "ApiAccessToken";

        public TokenHandler(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var ctx = _httpContextAccessor.HttpContext;

            // If the incoming browser request carries the ApiAccessToken cookie, extract
            // the JWT and forward it to the API as a Bearer token. If the cookie is
            // missing (unauthenticated request) the call goes out without an Authorization
            // header and the API will respond with 401 Unauthorized.
            if (ctx != null && ctx.Request.Cookies.TryGetValue(CookieName, out var token) && !string.IsNullOrWhiteSpace(token))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }

            return base.SendAsync(request, cancellationToken);
        }
    }
}