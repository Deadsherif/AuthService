using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;

namespace AuthService.Services
{
    public sealed class AuthApiClient
    {
        private static readonly HttpClient HttpClient = CreateClient();

        private static HttpClient CreateClient()
        {
            var client = new HttpClient
            {
                BaseAddress = new Uri(ApiEndpoints.BaseUrl)
            };
            client.DefaultRequestHeaders.Add("X-API-Key", ApiEndpoints.ApiKey);
            return client;
        }

        public async Task<AuthenticateResult> AuthenticateAsync(string company, string userName, string password)
        {
            try
            {
                using var response = await HttpClient.GetAsync(ApiEndpoints.Authenticate(company, userName, password)).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                    return new AuthenticateResult();

                var result = await response.Content.ReadFromJsonAsync<AuthenticateResult>().ConfigureAwait(false);
                return result ?? new AuthenticateResult { Authenticated = true };
            }
            catch
            {
                return new AuthenticateResult();
            }
        }

    }

    public sealed class AuthenticateResult
    {
        public bool Authenticated { get; set; }
        public string Company { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
    }
}

