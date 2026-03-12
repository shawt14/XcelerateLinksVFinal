using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace XcelerateLinks.Mvc.Http
{
    // ── LoggingHandler — HttpClient delegating handler (HTTP pipeline middleware) ──
    //
    // ASP.NET Core has two distinct "pipeline" concepts:
    //   1. The SERVER pipeline (app.Use*) — handles incoming requests from the browser.
    //   2. The CLIENT pipeline (DelegatingHandler chain) — handles outgoing HTTP calls
    //      made by HttpClient to the API backend.
    //
    // LoggingHandler is a component of the CLIENT pipeline. It is a DelegatingHandler,
    // which is the HttpClient equivalent of middleware. Every outgoing API call made
    // through the "Api" named HttpClient flows through this handler before the actual
    // HTTP request is sent over the wire, and again after the response is received.
    //
    // WHAT IT DOES
    // ------------
    // On each outbound request it logs:
    //   • The HTTP method and target URI (e.g., GET https://api/api/users/42)
    //   • All request headers and content-type headers (DEBUG level)
    //   • The full request body (INFO level)
    // On each response it logs:
    //   • The status code and reason phrase (e.g., 200 OK)
    //   • All response headers (DEBUG level)
    //   • The full response body (INFO level)
    // If an exception is thrown it logs the error and re-throws.
    //
    // WHY IT EXISTS
    // -------------
    // Because the MVC site communicates with the REST API over HTTP, it can be hard to
    // diagnose failures without seeing the raw request/response. This handler provides
    // full request/response visibility in the application log during development and
    // debugging without any changes to individual controllers or services.
    //
    // HANDLER CHAIN ORDER (registered in MVC Program.cs)
    //   HttpClient "Api" outbound call
    //     ──► TokenHandler   (attaches Authorization: Bearer header from cookie)
    //     ──► LoggingHandler (logs request + response)
    //     ──► Primary HttpClientHandler (sends the actual TCP request to the API)
    //
    // Note: LoggingHandler is registered with AddTransient<LoggingHandler>() but is NOT
    // added to the "Api" HttpClient pipeline via .AddHttpMessageHandler<LoggingHandler>().
    // It is available in the DI container but not yet wired into the handler chain.
    // To enable full request/response logging, add .AddHttpMessageHandler<LoggingHandler>()
    // to the builder.Services.AddHttpClient("Api", ...) call in MVC Program.cs.
    // ─────────────────────────────────────────────────────────────────────────────
    public class LoggingHandler : DelegatingHandler
    {
        private readonly ILogger<LoggingHandler> _logger;

        public LoggingHandler(ILogger<LoggingHandler> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            try
            {
                // Log request line + headers
                _logger.LogInformation("Outgoing HTTP request: {Method} {Uri}", request.Method, request.RequestUri);
                foreach (var h in request.Headers)
                    _logger.LogDebug("Req-Header: {Name}: {Value}", h.Key, string.Join(", ", h.Value));

                if (request.Content != null)
                {
                    foreach (var h in request.Content.Headers)
                        _logger.LogDebug("Req-Content-Header: {Name}: {Value}", h.Key, string.Join(", ", h.Value));

                    var reqBody = await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                    _logger.LogInformation("Request body: {Body}", string.IsNullOrWhiteSpace(reqBody) ? "(empty)" : reqBody);
                }

                var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

                // Log response status + headers
                _logger.LogInformation("Received HTTP response: {StatusCode} {ReasonPhrase}", (int)response.StatusCode, response.ReasonPhrase);
                foreach (var h in response.Headers)
                    _logger.LogDebug("Resp-Header: {Name}: {Value}", h.Key, string.Join(", ", h.Value));
                if (response.Content != null)
                {
                    foreach (var h in response.Content.Headers)
                        _logger.LogDebug("Resp-Content-Header: {Name}: {Value}", h.Key, string.Join(", ", h.Value));

                    var respBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                    // Keep response body safe-sized in logs - still print fully for now as we need full diagnostics
                    _logger.LogInformation("Response body (raw): {Body}", string.IsNullOrWhiteSpace(respBody) ? "(empty)" : respBody);
                }

                return response;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception while logging HTTP request/response");
                throw;
            }
        }
    }
}