using AuthService.Commands;
using AuthService.MVVM.Models;
using AuthService.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;

namespace AuthService.Services
{
    public class SubscriptionService
    {
        public static SubscriptionStatus Status { get; set; } = SubscriptionStatus.Error;

        private readonly HttpClient _httpClient;
        private const string RedemptionsUrl = "https://marketplace.firstoption-es.com/api/subscriptions/redemptions";
        private const string RedeeemUrl = "https://marketplace.firstoption-es.com/api/subscriptions/redeem";

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
                var task = _httpClient.GetAsync(url);
                var response = task.GetAwaiter().GetResult();
                response.EnsureSuccessStatusCode(); // Throws exception if status code is not 2xx
                string responseContent = await response.Content.ReadAsStringAsync();

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
                // Network or HTTP error
                return null;
            }
        }

        public async Task<ApiResponsePost> PostRedeemAsync(string code, string data)
        {
            try
            {
                string url = $"{RedeeemUrl}?code={code}&data[]={data}";
                var task = _httpClient.PostAsync(url, null);
                var response = task.GetAwaiter().GetResult();
                response.EnsureSuccessStatusCode();
                string responseContent = await response.Content.ReadAsStringAsync();

                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                };

                return JsonSerializer.Deserialize<ApiResponsePost>(responseContent, options);
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
                // Network or HTTP error
                return null;
            }
            catch (Exception)
            {
                // Other errors
                return null;
            }
        }

        


        public static List<string> GetAllMacAdressesFromPc()
        {
            List<string> allMacs = new List<string>();

            var allNetworks = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var net in allNetworks)
            {
                var OperationalStatus = net.OperationalStatus;
                var NetworkInterfaceType = net.NetworkInterfaceType;
                if (NetworkInterfaceType != NetworkInterfaceType.Loopback)
                {
                    var macAddress = net.GetPhysicalAddress().GetAddressBytes();
                    var strMac = string.Join(":", macAddress.Select(b => b.ToString("X2")));
                    allMacs.Add(strMac);
                }

            }
            return allMacs;
        }


        public static string GetCurrentMacAddress()
        {
            var allNetworks = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var net in allNetworks)
            {
                var OperationalStatus = net.OperationalStatus;
                var NetworkInterfaceType = net.NetworkInterfaceType;
                if (OperationalStatus == OperationalStatus.Up && NetworkInterfaceType != NetworkInterfaceType.Loopback)
                {
                    var macAddress = net.GetPhysicalAddress().GetAddressBytes();
                    var strMac = string.Join(":", macAddress.Select(b => b.ToString("X2")));
                    return strMac;
                }
            }
            return string.Empty;
        }



        public static int IsStringInList(List<string> stringList, string searchString)
        {
            if (stringList == null)
            {
                return -1;
            }
            return stringList.IndexOf(searchString);
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
