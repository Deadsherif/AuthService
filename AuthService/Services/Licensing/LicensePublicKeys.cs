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


        static LicensePublicKeys()
        {
            Pems["k1"] = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQrschhGf2ACmQiUwW6OIDLZ5nEKG" +
                "\nYCN0b3XW2l5LLEXl5lqYwBDIJsMOzmKIzNvgUMNAI5yb4K1cwxDUYtlZyQ==\n-----END PUBLIC KEY-----";
            // (add a second kid here later to rotate without bricking issued tokens)
        }

        public static ECDsa Resolve(string kid)
        {
            if (kid == null || !Pems.TryGetValue(kid, out var pem)) return null;

            // Any failure while decoding/parsing untrusted PEM material (bad base64, truncated
            // or malformed DER, wrong tags, wrong curve OID, wrong point length/marker) must
            // yield null - the same contract as an unknown kid - rather than throw, since
            // callers (the license-token verifier) treat null as "unknown/unusable key."
            ECDsa ec = null;
            try
            {
                var parameters = ParseP256SubjectPublicKeyInfo(DecodePem(pem));
                ec = ECDsa.Create();
                ec.ImportParameters(parameters);
                return ec;
            }
            catch (Exception ex) when (ex is FormatException
                                        || ex is CryptographicException
                                        || ex is IndexOutOfRangeException
                                        || ex is ArgumentException)
            {
                ec?.Dispose();
                return null;
            }
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

        // DER encoding of the OID content (no tag/length) for prime256v1 / P-256:
        // 1.2.840.10045.3.1.7 -> 06 08 2A 86 48 CE 3D 03 01 07
        private static readonly byte[] Prime256v1OidContent =
            { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };

        private static ECParameters ParseP256SubjectPublicKeyInfo(byte[] der)
        {
            var pos = 0;
            var outer = ReadTlv(der, ref pos); // outer SEQUENCE (whole SPKI)

            var inner = outer.ContentOffset;
            var algId = ReadTlv(der, ref inner); // AlgorithmIdentifier SEQUENCE
            var bitString = ReadTlv(der, ref inner); // BIT STRING wrapping the EC point

            // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY }.
            // For an EC key, algorithm is id-ecPublicKey and parameters is the named-curve OID.
            // The named-curve OID must be validated before the point below is trusted as a
            // P-256 point - otherwise a same-coordinate-length curve (e.g. secp256k1, which
            // also has 32-byte X/Y) could be silently force-fit into nistP256.
            var algPos = algId.ContentOffset;
            ReadTlv(der, ref algPos); // id-ecPublicKey OID - algorithm type, unused beyond EC dispatch
            var curveOid = ReadTlv(der, ref algPos); // namedCurve OID
            if (!OidContentEquals(der, curveOid, Prime256v1OidContent))
                throw new CryptographicException("Unsupported EC curve; only P-256 (prime256v1) is supported.");

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

        private static bool OidContentEquals(byte[] der, (int ContentOffset, int ContentLength) oid, byte[] expectedContent)
        {
            if (oid.ContentLength != expectedContent.Length) return false;
            for (var i = 0; i < expectedContent.Length; i++)
            {
                if (der[oid.ContentOffset + i] != expectedContent[i]) return false;
            }
            return true;
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
