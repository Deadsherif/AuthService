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
