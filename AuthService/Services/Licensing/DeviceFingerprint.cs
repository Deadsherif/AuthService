using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AuthService.Services.Licensing
{
    public static class DeviceFingerprint
    {
        public static string Hash(string[] components)
        {
            var joined = string.Join("|", components.Where(c => !string.IsNullOrEmpty(c)).OrderBy(c => c, StringComparer.Ordinal));
            using (var sha = SHA256.Create())
                return ToHex(sha.ComputeHash(Encoding.UTF8.GetBytes(joined)));
        }

        public static bool Matches(string tokenHash, string[] currentComponents, int minAgree = 3)
        {
            var present = currentComponents.Where(c => !string.IsNullOrEmpty(c)).ToArray();
            for (int size = present.Length; size >= minAgree; size--)
                foreach (var subset in Combinations(present, size))
                    if (string.Equals(Hash(subset), tokenHash, StringComparison.OrdinalIgnoreCase))
                        return true;
            return false;
        }

        public static string[] Components()
        {
            var list = new List<string>();
            TryAdd(list, ReadMachineGuid());
            TryAdd(list, ReadVolumeSerial());
            TryAdd(list, ReadPrimaryMac());
            return list.ToArray();
        }

        private static void TryAdd(List<string> l, string v) { if (!string.IsNullOrWhiteSpace(v)) l.Add(v); }

        // Registry-based MachineGuid read works identically on net47/net48.1/net8.0-windows;
        // no TFM-specific branching is needed here.
        private static string ReadMachineGuid()
        {
            try
            {
                using (var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography"))
                    return k?.GetValue("MachineGuid") as string;
            }
            catch { return null; }
        }

        private static string ReadVolumeSerial()
        {
            try
            {
                var root = System.IO.Path.GetPathRoot(Environment.SystemDirectory);
                var drive = new System.IO.DriveInfo(root);
                return drive.IsReady ? drive.VolumeLabel + ":" + root : null;
            }
            catch { return null; }
        }

        private static string ReadPrimaryMac()
        {
            try
            {
                return SubscriptionService.GetCurrentMacAddress();
            }
            catch { return null; }
        }

        private static IEnumerable<string[]> Combinations(string[] items, int k)
        {
            if (k == items.Length) { yield return items; yield break; }
            var idx = Enumerable.Range(0, k).ToArray();
            while (true)
            {
                yield return idx.Select(i => items[i]).ToArray();
                int p = k - 1;
                while (p >= 0 && idx[p] == items.Length - k + p) p--;
                if (p < 0) yield break;
                idx[p]++;
                for (int j = p + 1; j < k; j++) idx[j] = idx[j - 1] + 1;
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
