using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace AuthService.Services.Licensing
{
    public sealed class MintResult
    {
        public bool Success { get; set; }
        public string Token { get; set; }
        public string Error { get; set; }
    }

    public interface IMintClient
    {
        Task<MintResult> RequestTokenAsync(string code, string deviceId);
    }

    public static class ActivationEndpoints
    {
        public static string MintUrl =>
            Environment.GetEnvironmentVariable("FIRSTOPTION_MINT_URL") ?? "https://vercel-portal-auth-service.vercel.app/activate";

        public static string MarketplaceRedemptionsUrl =>
            Environment.GetEnvironmentVariable("FIRSTOPTION_MARKETPLACE_URL")
            ?? "https://marketplace.firstoption-es.com/api/subscriptions/redemptions";

        public static string MarketplaceRedeemUrl =>
            Environment.GetEnvironmentVariable("FIRSTOPTION_MARKETPLACE_REDEEM_URL")
            ?? "https://marketplace.firstoption-es.com/api/subscriptions/redeem";

        // The real mint service is "configured" once FIRSTOPTION_MINT_URL is set to a
        // real URL (not unset, not the placeholder). Until then the client uses the
        // legacy registration fallback.
        public static bool MintConfigured
        {
            get
            {
                var url = Environment.GetEnvironmentVariable("FIRSTOPTION_MINT_URL") ?? MintUrl ?? string.Empty;
                return !string.IsNullOrWhiteSpace(url) && url.IndexOf("REPLACE-ME.invalid", StringComparison.OrdinalIgnoreCase) < 0;
            }
        }
    }

    public sealed class HttpMintClient : IMintClient
    {
        private readonly HttpClient _http;
        private readonly string _url;

        public HttpMintClient(HttpClient http, string url) { _http = http; _url = url; }

        public async Task<MintResult> RequestTokenAsync(string code, string deviceId)
        {
            try
            {
                // NOTE: build the request body from a Dictionary, whose keys are runtime
                // string data, NOT an anonymous type. Post-obfuscation, ConfuserEx's rename
                // strips constructor/parameter names, and System.Text.Json's reflection
                // serializer maps an anonymous type via its constructor parameter names --
                // so `new { code, device }` throws ("deserialization constructor ... contains
                // parameters with null names") and activation fails. Dictionary keys are
                // immune to renaming.
                var payload = JsonSerializer.Serialize(new Dictionary<string, string>
                {
                    ["code"] = code,
                    ["device"] = deviceId
                });
                using var content = new StringContent(payload, Encoding.UTF8, "application/json");
                using var response = await _http.PostAsync(_url, content).ConfigureAwait(false);
                var body = response.Content == null ? string.Empty : await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                    return new MintResult { Success = false, Error = "Server rejected the code (" + (int)response.StatusCode + ")" };

                // A success status but a non-JSON body (e.g. an HTML error/interstitial
                // page from a proxy or tunnel) would make JsonDocument.Parse throw. Detect
                // that up front and surface a clear message instead of an exception.
                var trimmed = body?.TrimStart();
                if (string.IsNullOrEmpty(trimmed) || (trimmed[0] != '{' && trimmed[0] != '['))
                {
                    var snippet = trimmed == null ? string.Empty
                        : trimmed.Substring(0, Math.Min(120, trimmed.Length)).Replace("\r", " ").Replace("\n", " ");
                    return new MintResult
                    {
                        Success = false,
                        Error = "Activation server returned a non-JSON response (check the endpoint URL / server status). Body started with: " + snippet
                    };
                }

                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("token", out var t) && t.ValueKind == JsonValueKind.String)
                    return new MintResult { Success = true, Token = t.GetString() };

                return new MintResult { Success = false, Error = "Server did not return a token" };
            }
            catch (Exception ex)
            {
                return new MintResult { Success = false, Error = "Could not reach the activation server: " + ex.Message };
            }
        }
    }
}
