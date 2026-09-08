using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AuthService.Services.Licensing
{
    public sealed class StoredLicense
    {
        public string Token { get; set; }
        public DateTimeOffset MaxDateSeen { get; set; }
        public bool IsRevoked { get; set; }
    }

    public sealed class LicenseStore
    {
        private readonly string _path;
        private readonly string _legacyPath;

        public LicenseStore(string path) : this(path, null) { }

        private LicenseStore(string path, string legacyPath)
        {
            _path = path;
            _legacyPath = legacyPath;
        }

        // Production default: a dedicated license file under the same LocalApplicationData
        // root LocalAuthCache uses, kept in its own subfolder so it never collides with the
        // legacy forgeable cache file (which is being phased out by the license gate).
        public static LicenseStore Default()
        {
            return new LicenseStore(Path.Combine(DefaultRoot(), "license.json"));
        }

        // Each add-in owns a separate license.json. If the add-in-specific file has not
        // been created yet, Read() falls back to the old shared file. A successful gate
        // evaluation then writes the same token into the new location, migrating it without
        // forcing existing customers to activate again.
        public static LicenseStore Default(string addinId)
        {
            if (string.IsNullOrWhiteSpace(addinId))
                throw new ArgumentException("An add-in ID is required.", nameof(addinId));

            var root = DefaultRoot();
            var path = Path.Combine(root, AddinFolderName(addinId), "license.json");
            return new LicenseStore(path, Path.Combine(root, "license.json"));
        }

        // The file holds an opaque, tamper-checked, device-bound blob (see
        // LicenseBlobCodec) instead of readable JSON. A hand edit fails the MAC and
        // Decode returns null, which the gate treats as "no license" -> re-activate.
        public StoredLicense Read()
        {
            var path = File.Exists(_path) ? _path : _legacyPath;
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
            return LicenseBlobCodec.Decode(File.ReadAllBytes(path));
        }

        public void Write(StoredLicense license)
        {
            var dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
            File.WriteAllBytes(_path, LicenseBlobCodec.Encode(license));
        }

        public void Clear()
        {
            if (File.Exists(_path)) File.Delete(_path);
        }

        public void Revoke()
        {
            var license = Read();
            if (license == null) return;

            license.IsRevoked = true;
            Write(license);
        }

        private static string DefaultRoot() => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "FirstOption", "AuthService");

        private static string AddinFolderName(string addinId)
        {
            if (Guid.TryParse(addinId, out var guid))
                return guid.ToString("D");

            // Non-GUID IDs are hashed so they cannot escape the AuthService directory or
            // introduce characters that are invalid in a Windows path.
            using (var sha = SHA256.Create())
            {
                var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(addinId.Trim().ToUpperInvariant()));
                var name = new StringBuilder(bytes.Length * 2);
                foreach (var value in bytes) name.Append(value.ToString("x2"));
                return name.ToString();
            }
        }
    }
}
