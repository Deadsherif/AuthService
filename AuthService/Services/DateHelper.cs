using AuthService.MVVM.ViewModel;
using System;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;


namespace AuthService.Services
{
    public static class DateHelper
    {
        public static async Task<DateTime> GetCurrentDateFromWebAsync()
        {
            // Ensure TLS 1.2 is enabled for .NET Framework
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12 | System.Net.SecurityProtocolType.Tls11 | System.Net.SecurityProtocolType.Tls;
            
            using (HttpClient client = new HttpClient())
            {
                client.Timeout = TimeSpan.FromSeconds(10);
                // Add User-Agent header - some APIs require this
                client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
                // Add Accept header for JSON
                client.DefaultRequestHeaders.Add("Accept", "application/json");

                // Try aisenseapi.com first

                try
                {
                    if (!AuthViewModel.IsGetResponseNull)
                    {
                        return AuthViewModel.GetResponse.time;
                    }
                    throw new Exception("null GetResponse");
                }
                catch
                {

                    try
                    {
                        var task = client.GetAsync("https://aisenseapi.com/services/v1/datetime");
                        var response = task.GetAwaiter().GetResult();
                        response.EnsureSuccessStatusCode();
                        string content = await response.Content.ReadAsStringAsync();

                        var options = new JsonSerializerOptions
                        {
                            PropertyNameCaseInsensitive = true
                        };

                        var timeData = JsonSerializer.Deserialize<AisenseApiResponse>(content, options);
                        if (timeData != null && timeData.Datetime != DateTime.MinValue)
                        {
                            return new DateTime(timeData.Datetime.Year, timeData.Datetime.Month, timeData.Datetime.Day);
                        }
                    }
                    catch
                    {
                        // Try fallback service (ipgeolocation.io)
                        try
                        {
                            var task = client.GetAsync("https://api.ipgeolocation.io/timezone?apiKey=d27b8d6f8d6a4a899999d2e61aa6bab6&tz=UTC");
                            var response = task.GetAwaiter().GetResult();
                            response.EnsureSuccessStatusCode(); // Throws exception if status code is not 2xx
                            string content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                            var options = new JsonSerializerOptions
                            {
                                PropertyNameCaseInsensitive = true
                            };

                            var timeData = JsonSerializer.Deserialize<IpGeolocationApiResponse>(content, options);
                            if (timeData != null && timeData.DateTime != DateTime.MinValue)
                            {
                                return new DateTime(timeData.DateTime.Year, timeData.DateTime.Month, timeData.DateTime.Day);
                            }
                        }
                        catch
                        {
                            DateTime computerTime = DateTime.Now;
                            return new DateTime(computerTime.Year, computerTime.Month, computerTime.Day);
                        }
                    }
                }
            }
            
            // Fallback to UTC now if all web requests fail
            DateTime utcNow = DateTime.UtcNow;
            return new DateTime(utcNow.Year, utcNow.Month, utcNow.Day);
        }

        private class AisenseApiResponse
        {
            [JsonPropertyName("datetime")]
            [JsonConverter(typeof(DateTimeConverter))]
            public DateTime Datetime { get; set; }
        }

        private class IpGeolocationApiResponse
        {
            [JsonPropertyName("timezone")]
            public string Timezone { get; set; }

            [JsonPropertyName("timezone_offset")]
            public int TimezoneOffset { get; set; }

            [JsonPropertyName("timezone_offset_with_dst")]
            public int TimezoneOffsetWithDst { get; set; }

            [JsonPropertyName("date")]
            public string Date { get; set; }

            [JsonPropertyName("date_time")]
            [JsonConverter(typeof(DateTimeConverter))]
            public DateTime DateTime { get; set; }

            [JsonPropertyName("date_time_txt")]
            public string DateTimeTxt { get; set; }

            [JsonPropertyName("date_time_wti")]
            public string DateTimeWti { get; set; }

            [JsonPropertyName("date_time_ymd")]
            public string DateTimeYmd { get; set; }

            [JsonPropertyName("date_time_unix")]
            public double DateTimeUnix { get; set; }

            [JsonPropertyName("time_24")]
            public string Time24 { get; set; }

            [JsonPropertyName("time_12")]
            public string Time12 { get; set; }

            [JsonPropertyName("week")]
            public int Week { get; set; }

            [JsonPropertyName("month")]
            public int Month { get; set; }

            [JsonPropertyName("year")]
            public int Year { get; set; }

            [JsonPropertyName("year_abbr")]
            public string YearAbbr { get; set; }

            [JsonPropertyName("current_tz_abbreviation")]
            public string CurrentTzAbbreviation { get; set; }

            [JsonPropertyName("current_tz_full_name")]
            public string CurrentTzFullName { get; set; }

            [JsonPropertyName("standard_tz_abbreviation")]
            public string StandardTzAbbreviation { get; set; }

            [JsonPropertyName("standard_tz_full_name")]
            public string StandardTzFullName { get; set; }

            [JsonPropertyName("is_dst")]
            public bool IsDst { get; set; }

            [JsonPropertyName("dst_savings")]
            public int DstSavings { get; set; }

            [JsonPropertyName("dst_exists")]
            public bool DstExists { get; set; }

            [JsonPropertyName("dst_tz_abbreviation")]
            public string DstTzAbbreviation { get; set; }

            [JsonPropertyName("dst_tz_full_name")]
            public string DstTzFullName { get; set; }

            [JsonPropertyName("dst_start")]
            public string DstStart { get; set; }

            [JsonPropertyName("dst_end")]
            public string DstEnd { get; set; }
        }
    }
}
