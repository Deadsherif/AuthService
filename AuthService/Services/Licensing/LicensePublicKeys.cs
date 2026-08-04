using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace AuthService.Services.Licensing
{
    public static class LicensePublicKeys
    {
        // PRODUCTION: replace with real public-key PEMs, keyed by kid. Two slots enable rotation.
        private static readonly ConcurrentDictionary<string, string> Pems = new ConcurrentDictionary<string, string>();

        public static void LoadForTests(string kid, string pem) => Pems[kid] = pem;

        public static ECDsa Resolve(string kid)
        {
            if (kid == null || !Pems.TryGetValue(kid, out var pem)) return null;
            var ec = ECDsa.Create();
            ec.ImportParameters(ParseP256SubjectPublicKeyInfo(DecodePem(pem)));
            return ec;
        }

        // Neither ECDsa.ImportFromPem nor ECDsa.ImportSubjectPublicKeyInfo exist on net47/net48
        // in this SDK, so the PEM armor is stripped manually and the DER SubjectPublicKeyInfo
        // is parsed by hand to recover the raw EC point, which is then loaded via the
        // long-standing ECParameters/ImportParameters API available on every TFM
        // (net47, net48, net8.0-windows). Only P-256 (ES256) keys are supported.
        private static byte[] DecodePem(string pem)
        {
            var lines = pem.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            var sb = new System.Text.StringBuilder();
            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (trimmed.Length == 0 || trimmed.StartsWith("-----")) continue;
                sb.Append(trimmed);
            }
            return Convert.FromBase64String(sb.ToString());
        }

        private static ECParameters ParseP256SubjectPublicKeyInfo(byte[] der)
        {
            var pos = 0;
            var outer = ReadTlv(der, ref pos); // outer SEQUENCE (whole SPKI)

            var inner = outer.ContentOffset;
            ReadTlv(der, ref inner); // AlgorithmIdentifier SEQUENCE - not validated, skipped
            var bitString = ReadTlv(der, ref inner); // BIT STRING wrapping the EC point

            // BIT STRING content starts with a 1-byte "unused bits" count (expected 0),
            // followed by the uncompressed EC point: 0x04 || X || Y.
            var pointOffset = bitString.ContentOffset + 1;
            var pointLength = bitString.ContentLength - 1;
            if (pointLength != 65 || der[pointOffset] != 0x04)
                throw new CryptographicException("Unsupported EC public key encoding; expected uncompressed P-256 point.");

            var coordLength = 32;
            var x = new byte[coordLength];
            var y = new byte[coordLength];
            Array.Copy(der, pointOffset + 1, x, 0, coordLength);
            Array.Copy(der, pointOffset + 1 + coordLength, y, 0, coordLength);

            return new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y }
            };
        }

        private static (int ContentOffset, int ContentLength) ReadTlv(byte[] buf, ref int pos)
        {
            pos++; // skip tag byte
            int len = buf[pos];
            pos++;
            if ((len & 0x80) != 0)
            {
                var numLenBytes = len & 0x7F;
                len = 0;
                for (var i = 0; i < numLenBytes; i++)
                {
                    len = (len << 8) | buf[pos];
                    pos++;
                }
            }
            var contentOffset = pos;
            pos += len;
            return (contentOffset, len);
        }
    }
}
