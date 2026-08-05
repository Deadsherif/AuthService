using System;
using System.Security.Cryptography;
using System.Text;

namespace AuthService.Services.Licensing
{
    public static class DeviceFingerprint
    {
        public static string Hash(string deviceId)
        {
            if (deviceId == null) deviceId = string.Empty;
            using (var sha = SHA256.Create())
                return ToHex(sha.ComputeHash(Encoding.UTF8.GetBytes(deviceId)));
        }

        public static bool Matches(string tokenHash, string currentDeviceId)
        {
            if (string.IsNullOrEmpty(currentDeviceId) || string.IsNullOrEmpty(tokenHash))
                return false;
            return string.Equals(Hash(currentDeviceId), tokenHash, StringComparison.OrdinalIgnoreCase);
        }

        public static string CurrentDeviceId()
        {
            try
            {
                using (var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography"))
                    return (k?.GetValue("MachineGuid") as string) ?? string.Empty;
            }
            catch { return string.Empty; }
        }

        private static string ToHex(byte[] b)
        {
            var sb = new StringBuilder(b.Length * 2);
            foreach (var x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }
    }
}
