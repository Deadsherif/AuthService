using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace AuthService.Services.Licensing
{
    public static class DeviceFingerprint
    {
        internal static Action<string> DiagnosticWriter = message => Trace.WriteLine("[DeviceFingerprint] " + message);

        public static IReadOnlyList<string> LastDiagnostics { get; private set; } = Array.Empty<string>();

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
            const string subKey = @"SOFTWARE\Microsoft\Cryptography";
            const string valueName = "MachineGuid";

            var result = ReadMachineGuid(Registry.LocalMachine, subKey, valueName);

            if (string.IsNullOrEmpty(result) && Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess)
            {
                using (var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                {
                    var from64 = ReadMachineGuid(baseKey, subKey, valueName);
                    if (!string.IsNullOrEmpty(from64))
                    {
                        result = from64;
                    }
                }
            }

            return result;
        }

        static string ReadMachineGuid(RegistryKey hive, string subKey, string valueName)
        {
            using (var k = hive.OpenSubKey(subKey))
            {
                if (k == null)
                {
                    return string.Empty;
                }

                var raw = k.GetValue(valueName);
                if (raw == null)
                {

                    return string.Empty;
                }

                var guid = raw as string;
                if (guid == null)
                {

                    return string.Empty;
                }

                if (guid.Length == 0)
                {

                    return string.Empty;
                }

                return guid;
            }
        }

        private static string ToHex(byte[] b)
        {
            var sb = new StringBuilder(b.Length * 2);
            foreach (var x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }
    }
}
