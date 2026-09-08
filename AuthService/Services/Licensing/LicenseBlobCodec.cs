using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AuthService.Services.Licensing
{
    // Turns a StoredLicense into an opaque, tamper-checked, device-bound byte blob and
    // back. The goal is to make the on-disk license HARD to read and edit, not
    // impossible: a determined attacker who extracts the embedded salt from the
    // (obfuscated) assembly and reads the machine GUID can still rebuild the key.
    //
    // Design:
    //  * The key is DERIVED, never stored: key = SHA256(tag || salt || machineGuid).
    //    The machine GUID (via DeviceFingerprint) binds the file to this PC, so a copy
    //    taken to another machine no longer decodes. The token is already device-bound,
    //    so this adds no new restriction for honest users.
    //  * Encrypt-then-MAC. AES-CBC hides the fields; HMAC-SHA256 over the whole record
    //    rejects any hand edit. A single flipped byte makes Decode return null.
    //  * No reflection and no member names are used, so a renaming obfuscator can rename
    //    StoredLicense freely without breaking the on-disk format.
    internal static class LicenseBlobCodec
    {
        // File layout: MAGIC(4) VER(1) IV(16) CIPHER(...) MAC(32).
        private static readonly byte[] Magic = { 0x46, 0x4F, 0x4C, 0x31 }; // "FOL1"
        private const byte Version = 1;
        private const int IvLength = 16;
        private const int MacLength = 32;

        // Embedded salt. It is not a real secret (it ships in the assembly); constant
        // encryption in the obfuscator hides it, and it only has to raise the effort.
        // NOTE: this MUST be static readonly, not const. A const string keeps its literal
        // value in the metadata Constant table, which ConfuserEx constant encryption does
        // not touch, so the salt would leak in clear. As static readonly, the value is
        // assigned by an ldstr in the static constructor, which the obfuscator encrypts.
        private static readonly string Salt = "FO~c7b1f0a4-9d2e-4a83-8b16-license-ratchet-v1";

        public static byte[] Encode(StoredLicense license)
        {
            if (license == null) throw new ArgumentNullException(nameof(license));

            byte[] plaintext = WriteFields(license);
            byte[] iv = new byte[IvLength];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(iv);

            byte[] cipher = Transform(plaintext, iv, encrypt: true);

            // record = MAGIC VER IV CIPHER, then MAC appended over that record.
            using (var ms = new MemoryStream())
            {
                ms.Write(Magic, 0, Magic.Length);
                ms.WriteByte(Version);
                ms.Write(iv, 0, iv.Length);
                ms.Write(cipher, 0, cipher.Length);
                byte[] record = ms.ToArray();

                byte[] mac = Mac(record);
                byte[] output = new byte[record.Length + mac.Length];
                Buffer.BlockCopy(record, 0, output, 0, record.Length);
                Buffer.BlockCopy(mac, 0, output, record.Length, mac.Length);
                return output;
            }
        }

        // Returns null on anything wrong: bad magic/version, a failed MAC (tamper),
        // truncation, or a decrypt/parse error. Callers treat null as "no license".
        public static StoredLicense Decode(byte[] blob)
        {
            try
            {
                int headerLength = Magic.Length + 1 + IvLength;
                if (blob == null || blob.Length < headerLength + MacLength) return null;

                for (int i = 0; i < Magic.Length; i++)
                    if (blob[i] != Magic[i]) return null;
                if (blob[Magic.Length] != Version) return null;

                int recordLength = blob.Length - MacLength;
                byte[] record = new byte[recordLength];
                Buffer.BlockCopy(blob, 0, record, 0, recordLength);
                byte[] mac = new byte[MacLength];
                Buffer.BlockCopy(blob, recordLength, mac, 0, MacLength);

                if (!FixedTimeEquals(mac, Mac(record))) return null;

                byte[] iv = new byte[IvLength];
                Buffer.BlockCopy(blob, Magic.Length + 1, iv, 0, IvLength);
                int cipherLength = recordLength - headerLength;
                byte[] cipher = new byte[cipherLength];
                Buffer.BlockCopy(blob, headerLength, cipher, 0, cipherLength);

                byte[] plaintext = Transform(cipher, iv, encrypt: false);
                return ReadFields(plaintext);
            }
            catch (Exception ex) when (ex is CryptographicException
                                        || ex is IOException
                                        || ex is EndOfStreamException
                                        || ex is FormatException
                                        || ex is ArgumentException)
            {
                return null;
            }
        }

        private static byte[] WriteFields(StoredLicense license)
        {
            using (var ms = new MemoryStream())
            using (var w = new BinaryWriter(ms, Encoding.UTF8))
            {
                w.Write((byte)1); // payload schema version
                w.Write(license.Token ?? string.Empty);
                w.Write(license.MaxDateSeen.UtcTicks);
                w.Write(license.IsRevoked);
                w.Flush();
                return ms.ToArray();
            }
        }

        private static StoredLicense ReadFields(byte[] plaintext)
        {
            using (var ms = new MemoryStream(plaintext, writable: false))
            using (var r = new BinaryReader(ms, Encoding.UTF8))
            {
                r.ReadByte(); // payload schema version (only 1 today)
                string token = r.ReadString();
                long utcTicks = r.ReadInt64();
                bool revoked = r.ReadBoolean();
                return new StoredLicense
                {
                    Token = token,
                    MaxDateSeen = new DateTimeOffset(utcTicks, TimeSpan.Zero),
                    IsRevoked = revoked
                };
            }
        }

        private static byte[] Transform(byte[] data, byte[] iv, bool encrypt)
        {
            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = DeriveKey("ENC");
                aes.IV = iv;
                using (var transform = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor())
                    return transform.TransformFinalBlock(data, 0, data.Length);
            }
        }

        private static byte[] Mac(byte[] record)
        {
            using (var hmac = new HMACSHA256(DeriveKey("MAC")))
                return hmac.ComputeHash(record);
        }

        // key = SHA256( tag || Salt || machineGuid ). 32 bytes, fits AES-256 and HMAC.
        private static byte[] DeriveKey(string tag)
        {
            string machineGuid = null;
            try { machineGuid = DeviceFingerprint.CurrentDeviceId(); } catch { }
            if (string.IsNullOrEmpty(machineGuid)) machineGuid = string.Empty;

            using (var sha = SHA256.Create())
                return sha.ComputeHash(Encoding.UTF8.GetBytes(tag + "|" + Salt + "|" + machineGuid));
        }

        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }
}
