using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace OfflineActivationClient
{
    public static class DeviceId
    {
        // MUST stay byte-identical to AuthService DeviceFingerprint.Hash / CurrentDeviceId.
        public static string Sha256Hex(string s)
        {
            if (s == null) s = string.Empty;
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(s));
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        public static string ReadMachineGuid()
        {
            const string subKey = @"SOFTWARE\Microsoft\Cryptography";
            const string valueName = "MachineGuid";

            var guid = ReadMachineGuid(Registry.LocalMachine, subKey, valueName);
            if (!string.IsNullOrEmpty(guid))
                return guid;

            if (Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess)
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                return ReadMachineGuid(baseKey, subKey, valueName);
            }

            return string.Empty;
        }

        static string ReadMachineGuid(RegistryKey hive, string subKey, string valueName)
        {
            using var k = hive.OpenSubKey(subKey);
            return (k?.GetValue(valueName) as string) ?? string.Empty;
        }

        public static string Compute() => Sha256Hex(ReadMachineGuid());
    }
}
