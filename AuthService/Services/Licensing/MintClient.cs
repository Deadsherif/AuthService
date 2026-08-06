using System;
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
            Environment.GetEnvironmentVariable("FIRSTOPTION_MINT_URL") ?? "https://REPLACE-ME.invalid/activate";

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
                var url = Environment.GetEnvironmentVariable("FIRSTOPTION_MINT_URL");
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
                var payload = JsonSerializer.Serialize(new { code, device = deviceId });
                using var content = new StringContent(payload, Encoding.UTF8, "application/json");
                using var response = await _http.PostAsync(_url, content).ConfigureAwait(false);
                var body = response.Content == null ? string.Empty : await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                    return new MintResult { Success = false, Error = "Server rejected the code (" + (int)response.StatusCode + ")" };

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
