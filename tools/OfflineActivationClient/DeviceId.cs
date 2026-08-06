using System.Security.Cryptography;
using System.Text;

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
            try
            {
                using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
                return (k?.GetValue("MachineGuid") as string) ?? string.Empty;
            }
            catch { return string.Empty; }
        }

        public static string Compute() => Sha256Hex(ReadMachineGuid());
    }
}
