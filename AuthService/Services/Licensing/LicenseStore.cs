using System;
using System.IO;
using System.Text.Json;

namespace AuthService.Services.Licensing
{
    public sealed class StoredLicense
    {
        public string Token { get; set; }
        public DateTimeOffset MaxDateSeen { get; set; }
    }

    public sealed class LicenseStore
    {
        private readonly string _path;
        public LicenseStore(string path) { _path = path; }

        // Production default: a dedicated license file under the same LocalApplicationData
        // root LocalAuthCache uses, kept in its own subfolder so it never collides with the
        // legacy forgeable cache file (which is being phased out by the license gate).
        public static LicenseStore Default()
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "FirstOption", "AuthService");
            return new LicenseStore(Path.Combine(dir, "license.json"));
        }

        public StoredLicense Read()
        {
            try { return File.Exists(_path) ? JsonSerializer.Deserialize<StoredLicense>(File.ReadAllText(_path)) : null; }
            catch { return null; }
        }

        public void Write(StoredLicense license)
        {
            var dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(_path, JsonSerializer.Serialize(license));
        }

        public void Clear() { try { if (File.Exists(_path)) File.Delete(_path); } catch { } }
    }
}
