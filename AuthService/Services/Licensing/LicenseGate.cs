using System;

namespace AuthService.Services.Licensing
{
    public enum GateStatus { Valid, Invalid, Rollback }

    public sealed class LicenseGate
    {
        private readonly LicenseStore _store;
        private readonly LicenseTokenVerifier _verifier = new LicenseTokenVerifier();

        public LicenseGate(LicenseStore store) { _store = store; }

        public GateStatus Evaluate(string addinId, string currentDeviceId, DateTimeOffset now, DateTimeOffset? onlineNow = null)
        {
            var stored = _store.Read();
            if (stored == null) return GateStatus.Invalid;

            // Rollback vs the highest date ever persisted (cheap, pre-verify — also rejects
            // a garbage token whose clock is rolled back without doing crypto work). Uses the
            // LOCAL clock only: an untrusted online reading must never influence what counts
            // as a rollback, or a bogus source could brick the ratchet.
            if (now < stored.MaxDateSeen) return GateStatus.Rollback;

            // Signature must verify. The verifier reports Expired using the raw clock, but the
            // gate is the authority on expiry (below) — so both Valid and Expired mean "signature
            // verified, claims trustworthy". Anything else (BadSignature/Malformed/UnknownKey) fails.
            var result = _verifier.Verify(stored.Token, now);
            if (result.Status != VerifyStatus.Valid && result.Status != VerifyStatus.Expired)
                return GateStatus.Invalid;

            var claims = result.Claims;

            // iat floor: "now" can never legitimately precede the moment the token was signed.
            // LOCAL clock only, same reasoning as the rollback check above.
            var floor = stored.MaxDateSeen;
            if (claims.IssuedAt > floor) floor = claims.IssuedAt;
            if (now < floor) return GateStatus.Rollback;

            // Expiry detection may additionally consider an untrusted online time reading, but
            // ONLY here — never for rollback/floor/persist above. This lets a bogus/attacker-
            // controlled online source detect (or falsely claim) expiry without ever being able
            // to ratchet the persisted MaxDateSeen forward, which would otherwise let a single
            // bad reading permanently self-lock every future honest run.
            var expiryTime = now > floor ? now : floor;
            if (onlineNow.HasValue && onlineNow.Value > expiryTime) expiryTime = onlineNow.Value;
            if (expiryTime > claims.Expires) return GateStatus.Invalid;

            if (!string.Equals(claims.AddonId, addinId, StringComparison.OrdinalIgnoreCase))
                return GateStatus.Invalid;

            if (!DeviceFingerprint.Matches(claims.DeviceHash, currentDeviceId))
                return GateStatus.Invalid;

            // Advance the ratchet forward by both `now` and `iat`, and persist.
            var advanced = new RollbackRatchet { MaxDateSeen = stored.MaxDateSeen }
                .Advance(now).Advance(claims.IssuedAt).MaxDateSeen;
            _store.Write(new StoredLicense { Token = stored.Token, MaxDateSeen = advanced });
            return GateStatus.Valid;
        }
    }
}
