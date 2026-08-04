using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.Services.Licensing
{
    public enum VerifyStatus { Valid, BadSignature, Expired, Malformed, UnknownKey }

    public sealed class VerifyResult
    {
        public VerifyStatus Status { get; set; }
        public LicenseClaims Claims { get; set; }
    }

    public sealed class LicenseTokenVerifier
    {
        public VerifyResult Verify(string jwt, DateTimeOffset now)
        {
            if (string.IsNullOrWhiteSpace(jwt)) return new VerifyResult { Status = VerifyStatus.Malformed };

            JwtSecurityToken parsed;
            try { parsed = new JwtSecurityTokenHandler().ReadJwtToken(jwt); }
            catch { return new VerifyResult { Status = VerifyStatus.Malformed }; }

            if (!string.Equals(parsed.Header.Alg, "ES256", StringComparison.Ordinal))
                return new VerifyResult { Status = VerifyStatus.BadSignature };

            var ec = LicensePublicKeys.Resolve(parsed.Header.Kid);
            if (ec == null) return new VerifyResult { Status = VerifyStatus.UnknownKey };

            var parameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false, // we compare exp ourselves against injected 'now'
                IssuerSigningKey = new ECDsaSecurityKey(ec)
                {
                    // Microsoft.IdentityModel caches signature providers keyed by the key's id.
                    // Multiple vectors in this test suite share the same kid ("k1"), so without
                    // disabling the cache, the 2nd+ ValidateToken call for that kid can reuse
                    // (or throw ObjectDisposedException against) a stale cached provider.
                    CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
                },
                ValidAlgorithms = new[] { "ES256" }
            };

            try
            {
                new JwtSecurityTokenHandler().ValidateToken(jwt, parameters, out _);
            }
            catch
            {
                return new VerifyResult { Status = VerifyStatus.BadSignature };
            }

            var claims = LicenseClaims.FromJwtPayload(
                parsed.Payload.ToDictionary(kv => kv.Key, kv => kv.Value));

            if (now > claims.Expires)
                return new VerifyResult { Status = VerifyStatus.Expired, Claims = claims };

            return new VerifyResult { Status = VerifyStatus.Valid, Claims = claims };
        }
    }
}
