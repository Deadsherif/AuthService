using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;

namespace AuthService.Services
{
    public sealed class AdminApiClient
    {
        private static readonly HttpClient HttpClient = CreateClient();
        private readonly string _company;

        public AdminApiClient(string company)
        {
            _company = company?.Trim() ?? string.Empty;
        }

        private static HttpClient CreateClient()
        {
            var client = new HttpClient
            {
                BaseAddress = new Uri(ApiEndpoints.BaseUrl),
                Timeout =  TimeSpan.FromSeconds(2)
            };
            client.DefaultRequestHeaders.Add("X-API-Key", ApiEndpoints.ApiKey);
            return client;
        }
    }

}
