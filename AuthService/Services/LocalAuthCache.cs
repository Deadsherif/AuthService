using AuthService.MVVM.View;
using AuthService.MVVM.ViewModel;
using AuthService8.MVVM.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace AuthService.Services
{
    public static class LocalAuthCache
    {
        public static string _code {  get; set; }
        private static readonly byte[] EncryptionKey = new byte[32]
        {
            0x55, 0x42, 0x1A, 0x9C, 0xD3, 0xF4, 0xA7, 0x18,
            0x32, 0x04, 0x5E, 0x6B, 0x9D, 0x0F, 0xC1, 0xB2,
            0x73, 0x8D, 0xAA, 0x19, 0x48, 0x02, 0xEF, 0xCE,
            0x67, 0x33, 0x91, 0x5B, 0xA4, 0x7E, 0xCD, 0x21
        };

        private static readonly byte[] InitializationVector = new byte[16]
        {
            0x12, 0x44, 0x3B, 0x88, 0x7E, 0x91, 0xAF, 0x04,
            0x59, 0x62, 0x37, 0x28, 0xC3, 0xDE, 0x50, 0x11
        };

        private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        };

        private static readonly string CacheFolderGuid = "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8";
        private static readonly string CacheFileName = "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8.BIN";

        private static string CachePath =>
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp", CacheFolderGuid, CacheFileName);

        public static async Task<bool> TryGetValidEntry(string caller, string addinID)
        {
            try
            {
                var currentMac = SubscriptionService.GetCurrentMacAddress();
                if (string.IsNullOrWhiteSpace(currentMac))
                {
                    return false;
                }

                var cache = ReadCache();
                if (cache == null)
                {
                    return false;
                }
               cache.Entries.TryGetValue(caller, out LocalCacheEntry entry);
                if (entry == null)
                {
                    return false;
                }
                bool SilentAuthResult = true;
                DateTime currentDate = await DateHelper.GetCurrentDateFromWebAsync();
                if (currentDate > entry.TimeStamp)
                {
                    SilentAuthResult = await SilentAuth(entry, currentDate);
                    if (!SilentAuthResult)
                    {
                        return false;
                    }
                    else
                    {
                        return true;
                    }
                }
                var storedMac = entry.Mac;
                if (storedMac == null)
                {
                    return false;
                }
                return string.Equals(NormalizeMac(storedMac), NormalizeMac(currentMac), StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        public static async Task<bool> SilentAuth(LocalCacheEntry entry, DateTime currentDate)
        {
            var code = entry.code;
            try
            {
                ApiResponseGet response = null;
                var _subscriptionService = new SubscriptionService();
                for (int i = 0; i < 5; i++)
                {
                    response = await _subscriptionService.GetRedemptionsAsync(code);
                    if (response != null)
                        break;
                }
                if (response == null)
                    return false;
                if (!response.Success)
                {
                    return false;
                }
                var subscription = response.Payload.Subscription;
                if (!string.Equals(subscription.Status, "active", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
                var redemptions = response.Payload.Redemptions.FirstOrDefault();
                string dataStr = redemptions.Data.First();
                List<string> validMacs = new List<string>();
                if (!IsMacValid(validMacs, dataStr))
                {
                    return false;
                }
                
                var EndDate = subscription.EndDate;
                if (currentDate > EndDate)
                {
                    return false;
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static bool IsMacValid(List<string> validMacs, string dataStr)
        {
            var parts = dataStr.Split(',');

            // Regex to validate MAC address (XX:XX:XX:XX:XX:XX)
            var macRegex = new Regex(@"^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$");

            foreach (var part in parts)
            {
                var trimmed = part.Trim();
                if (!macRegex.IsMatch(trimmed))
                {
                    break;
                }
                validMacs.Add(trimmed);
            }

            var currentMac = SubscriptionService.GetCurrentMacAddress();
            return validMacs.IndexOf(currentMac) >= 0;
        }
        public static bool UpsertCurrentMac(string caller)
        {
            try
            {
                var currentMac = SubscriptionService.GetCurrentMacAddress();
                if (string.IsNullOrWhiteSpace(currentMac))
                {
                    return false;
                }
                _ = WriteCache(caller, currentMac);
                return true;
            }
            catch
            {
                return false;
            }

        }

        public static LocalCacheFile ReadCache()
        {
            try
            {
                if (!File.Exists(CachePath))
                {
                    return null;
                }

                var encryptedBytes = File.ReadAllBytes(CachePath);
                var json = Decrypt(encryptedBytes);

                if (string.IsNullOrWhiteSpace(json))
                {
                    return null;
                }

                return JsonSerializer.Deserialize<LocalCacheFile>(json, JsonOptions);
            }
            catch
            {
                return null;
            }
        }

        private static async Task WriteCache(string caller, string mac)
        {
            try
            {
                if(_code == null)
                {
                    return;
                }
                var localCacheEntry = new LocalCacheEntry
                {
                    AddinName = caller,
                    Mac = mac,
                    TimeStamp = await DateHelper.GetCurrentDateFromWebAsync(),
                    code = _code
                };

                var directory = Path.GetDirectoryName(CachePath);
                if (!Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }
                var cache = ReadCache();
                if(cache == null)
                {
                    cache = new LocalCacheFile();
                }
                if (!cache.Entries.ContainsKey(caller))
                {
                    cache.Entries.Add(caller, localCacheEntry);
                }
                else
                {
                    cache.Entries[caller] = localCacheEntry;
                }

                var json = JsonSerializer.Serialize(cache, JsonOptions);
                var encryptedBytes = Encrypt(json);
                File.WriteAllBytes(CachePath, encryptedBytes);
            }
            catch
            {
                // Swallow errors to avoid blocking the user flow.
            }
        }

        private static byte[] Encrypt(string plainText)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = EncryptionKey;
                aes.IV = InitializationVector;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var memoryStream = new MemoryStream())
                using (var cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                using (var writer = new StreamWriter(cryptoStream, Encoding.UTF8))
                {
                    writer.Write(plainText);
                    writer.Flush();
                    cryptoStream.FlushFinalBlock();
                    return memoryStream.ToArray();
                }
            }
        }

        private static string Decrypt(byte[] cipherBytes)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = EncryptionKey;
                aes.IV = InitializationVector;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var memoryStream = new MemoryStream(cipherBytes))
                using (var cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                using (var reader = new StreamReader(cryptoStream, Encoding.UTF8))
                {
                    return reader.ReadToEnd();
                }
            }
        }


        private static string NormalizeMac(string mac)
        {
            if (string.IsNullOrWhiteSpace(mac))
            {
                return string.Empty;
            }

            var builder = new StringBuilder(mac.Length);
            foreach (var c in mac)
            {
                if (c != ':' && c != '-' && c != ' ')
                {
                    builder.Append(char.ToUpperInvariant(c));
                }
            }
            return builder.ToString();
        }
    }
}

