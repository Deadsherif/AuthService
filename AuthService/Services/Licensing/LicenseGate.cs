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

            var ratchet = new RollbackRatchet { MaxDateSeen = stored.MaxDateSeen };
            if (ratchet.IsRollback(now)) return GateStatus.Rollback;

            var result = _verifier.Verify(stored.Token, now);
            if (result.Status != VerifyStatus.Valid) return GateStatus.Invalid;

            if (!string.Equals(result.Claims.AddonId, addinId, StringComparison.OrdinalIgnoreCase))
                return GateStatus.Invalid;

            if (!DeviceFingerprint.Matches(result.Claims.DeviceHash, currentDeviceId))
                return GateStatus.Invalid;

            _store.Write(new StoredLicense { Token = stored.Token, MaxDateSeen = ratchet.Advance(now).MaxDateSeen });
            return GateStatus.Valid;
        }
    }
}
