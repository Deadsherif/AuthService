using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace AuthService.Services.Licensing
{
    public sealed class LegacyActivationResult
    {
        public bool CodeValid { get; set; }
        public bool Registered { get; set; }
        public string Error { get; set; }
    }

    public interface ILegacyActivationClient
    {
        Task<LegacyActivationResult> RegisterAsync(string code, string deviceHash, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken));
    }

    // Interim fallback used until the real mint service is deployed. Validates the code
    // against the marketplace the old way (GET redemptions), then registers the device
    // hash (POST redeem, data[]=hash). It NEVER grants access - the provider reads the
    // registered hashes from the marketplace DB and mints tokens manually.
    public sealed class HttpLegacyActivationClient : ILegacyActivationClient
    {
        private readonly HttpClient _http;
        private readonly string _redemptionsUrl;
        private readonly string _redeemUrl;

        public HttpLegacyActivationClient(HttpClient http, string redemptionsUrl, string redeemUrl)
        {
            _http = http;
            _redemptionsUrl = redemptionsUrl;
            _redeemUrl = redeemUrl;
        }

        public async Task<LegacyActivationResult> RegisterAsync(string code, string deviceHash, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            try
            {
                var getUrl = _redemptionsUrl + "?code=" + Uri.EscapeDataString(code);
                using (var getResp = await _http.GetAsync(getUrl, cancellationToken).ConfigureAwait(false))
                {
                    if (!getResp.IsSuccessStatusCode)
                        return new LegacyActivationResult { CodeValid = false, Error = "Code not found or server unavailable" };

                    var getBody = getResp.Content == null ? string.Empty : await getResp.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (!JsonSuccess(getBody))
                        return new LegacyActivationResult { CodeValid = false, Error = "Code not found" };
                }

                // Matches the original master redeem call verbatim: raw code, literal
                // data[] array key, raw data value (marketplace expects PHP-style data[]).
                var postUrl = _redeemUrl + "?code=" + code + "&data[]=" + deviceHash;
                using (var postResp = await _http.PostAsync(postUrl, null, cancellationToken).ConfigureAwait(false))
                {
                    if (!postResp.IsSuccessStatusCode)
                        return new LegacyActivationResult { CodeValid = true, Registered = false, Error = "Could not register this device" };
                    return new LegacyActivationResult { CodeValid = true, Registered = true };
                }
            }
            catch (Exception)
            {
                return new LegacyActivationResult { CodeValid = false, Registered = false, Error = "Could not reach the activation server" };
            }
        }

        private static bool JsonSuccess(string body)
        {
            try
            {
                using (var doc = JsonDocument.Parse(body))
                    return doc.RootElement.TryGetProperty("success", out var s)
                        && s.ValueKind == JsonValueKind.True;
            }
            catch { return false; }
        }
    }
}
