using System;

namespace AuthService.Services.Licensing
{
    public enum GateStatus { Valid, Invalid, Rollback }

    public sealed class LicenseGate
    {
        private readonly LicenseStore _store;
        private readonly LicenseTokenVerifier _verifier = new LicenseTokenVerifier();

        public LicenseGate(LicenseStore store) { _store = store; }

        public GateStatus Evaluate(string addinId, string currentDeviceId, DateTimeOffset now)
        {
            var stored = _store.Read();
            if (stored == null) return GateStatus.Invalid;

            // Rollback vs the highest date ever persisted (cheap, pre-verify — also rejects
            // a garbage token whose clock is rolled back without doing crypto work).
            if (now < stored.MaxDateSeen) return GateStatus.Rollback;

            // Signature must verify. The verifier reports Expired using the raw clock, but the
            // gate is the authority on expiry (below) — so both Valid and Expired mean "signature
            // verified, claims trustworthy". Anything else (BadSignature/Malformed/UnknownKey) fails.
            var result = _verifier.Verify(stored.Token, now);
            if (result.Status != VerifyStatus.Valid && result.Status != VerifyStatus.Expired)
                return GateStatus.Invalid;

            var claims = result.Claims;

            // iat floor: "now" can never legitimately precede the moment the token was signed.
            var floor = stored.MaxDateSeen;
            if (claims.IssuedAt > floor) floor = claims.IssuedAt;
            if (now < floor) return GateStatus.Rollback;

            // Decide expiry against the ratchet max, never the raw clock, so a rolled-back
            // clock can never un-expire a token.
            var effectiveNow = now > floor ? now : floor;
            if (effectiveNow > claims.Expires) return GateStatus.Invalid;

            if (!string.Equals(claims.AddonId, addinId, StringComparison.OrdinalIgnoreCase))
                return GateStatus.Invalid;

            if (!DeviceFingerprint.Matches(claims.DeviceHash, currentDeviceId))
                return GateStatus.Invalid;

            // Advance the ratchet forward by both the observed clock and the iat floor, and persist.
            var advanced = new RollbackRatchet { MaxDateSeen = stored.MaxDateSeen }
                .Advance(now).Advance(claims.IssuedAt).MaxDateSeen;
            _store.Write(new StoredLicense { Token = stored.Token, MaxDateSeen = advanced });
            return GateStatus.Valid;
        }
    }
}
