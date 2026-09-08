using AuthService.Commands;
using AuthService.Services;
using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;

namespace AuthService.Services
{
    public class SubscriptionService
    {
        public static SubscriptionStatus Status { get; private set; } = SubscriptionStatus.Error;

        internal static void SetStatus(SubscriptionStatus s) => Status = s;

        private readonly HttpClient _httpClient;
        // static readonly, not const: a const string keeps its value in the metadata
        // Constant table (which the obfuscator's constant encryption does not touch), so
        // the URL would leak in clear. As static readonly it is an encrypted ldstr.
        private static readonly string RedemptionsUrl = "https://marketplace.firstoption-es.com/api/subscriptions/redemptions";

        public SubscriptionService()
        {
            _httpClient = new HttpClient();
            _httpClient.Timeout = TimeSpan.FromSeconds(5);
            // Add User-Agent header - some APIs require this
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            // Add Accept header for JSON
            _httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
        }

        public async Task<ApiResponseGet> GetRedemptionsAsync(string code)
        {
            try
            {
                string encodedCode = Uri.EscapeDataString(code);
                string url = $"{RedemptionsUrl}?code={encodedCode}";
                HttpResponseMessage response = await _httpClient.GetAsync(url).ConfigureAwait(false);
                response.EnsureSuccessStatusCode(); // Throws exception if status code is not 2xx
                string responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                };

                return JsonSerializer.Deserialize<ApiResponseGet>(responseContent, options);
            }
            catch (TaskCanceledException)
            {
                // Timeout occurred
                return null;
            }
            catch (System.TimeoutException)
            {
                // Timeout occurred
                return null;
            }
            catch (HttpRequestException)
            {
                return null;
            }
        }


        public void Dispose()
        {
            _httpClient?.Dispose();
        }

        public enum SubscriptionStatus
        {
            Valid,
            Expired,
            NotFound,
            Error
        }
    }
}
