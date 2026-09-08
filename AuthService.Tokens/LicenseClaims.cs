using System;
using System.Collections.Generic;
using System.Globalization;

namespace AuthService.Services.Licensing
{
    public sealed class LicenseClaims
    {
        public string Issuer { get; set; }
        public string AddonId { get; set; }
        public string Tier { get; set; }
        public DateTimeOffset IssuedAt { get; set; }
        public DateTimeOffset Expires { get; set; }
        public string DeviceHash { get; set; }
        public string TokenId { get; set; }

        public static LicenseClaims FromJwtPayload(IDictionary<string, object> claims)
        {
            return new LicenseClaims
            {
                Issuer = Str(claims, "iss"),
                AddonId = Str(claims, "addon"),
                Tier = Str(claims, "tier"),
                IssuedAt = DateTimeOffset.FromUnixTimeSeconds(Long(claims, "iat")),
                Expires = DateTimeOffset.FromUnixTimeSeconds(Long(claims, "exp")),
                DeviceHash = Str(claims, "device"),
                TokenId = Str(claims, "jti")
            };
        }

        private static string Str(IDictionary<string, object> c, string k) =>
            c.TryGetValue(k, out var v) ? Convert.ToString(v, CultureInfo.InvariantCulture) : null;

        private static long Long(IDictionary<string, object> c, string k) =>
            c.TryGetValue(k, out var v) ? Convert.ToInt64(v, CultureInfo.InvariantCulture) : 0L;
    }
}
