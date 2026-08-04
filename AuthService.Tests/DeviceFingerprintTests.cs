using AuthService.Services.Licensing;
using Xunit;

public class DeviceFingerprintTests
{
    [Fact]
    public void Hash_IsStableAndOrderIndependent()
    {
        var a = DeviceFingerprint.Hash(new[] { "guid-x", "vol-y", "mac-z" });
        var b = DeviceFingerprint.Hash(new[] { "mac-z", "guid-x", "vol-y" });
        Assert.Equal(a, b);
    }

    // NOTE ON THIS TEST: this is the brief's own reference scenario, included verbatim
    // for continuity with the task-5 brief. It is SKIPPED because it is mathematically
    // unsatisfiable by any correct implementation of the specified contract, not because
    // of a bug in this implementation:
    //
    //   Hash(components) = SHA-256("|"-joined sorted components)  (pinned -- required
    //   verbatim by the TEST-DEVICE continuity vector, see the two tests below).
    //
    //   token = Hash(original)  is the SHA-256 digest of the FULL 3-item string
    //   "guid-x|mac-z|vol-y". SHA-256 is preimage-resistant: no other input (in
    //   particular, no shorter or differently-valued joined string produced by any
    //   subset of a component set with one value replaced) can hash to that same
    //   digest, except with cryptographically negligible probability. Matches() can
    //   only ever recompute Hash() over CURRENT components/subsets thereof and compare
    //   the digest -- it has no way to "partially" match a hash that encodes exact
    //   byte content of ALL originally-hashed components.
    //
    //   Empirically verified (see task-5-report.md): every subset of
    //   {"guid-x","vol-y","mac-DIFFERENT"} of size 2 and 3 hashes to a value different
    //   from Hash({"guid-x","vol-y","mac-z"}). This holds for ANY correct combinations
    //   enumerator, not just this one -- the combinations code is not the culprit.
    //
    //   What the subset-matching mechanism CAN actually do: tolerate a component that
    //   was UNAVAILABLE at enrollment later becoming available (enrollment hashed a
    //   smaller set; that same smaller set is still a byte-identical subset of the
    //   larger current set) -- see Matches_TreatsNewlyAvailableComponent_AsCompatible
    //   below for a demonstration that genuinely passes.
    [Fact(Skip = "Unsatisfiable by design: SHA-256 preimage resistance means no subset of a " +
                 "value-changed current set can ever reproduce a hash computed over the full " +
                 "original set. See comment above and task-5-report.md for the proof. Flagged " +
                 "for the plan owner -- this is a brief/spec bug, not an implementation bug.")]
    public void Matches_ToleratesOneChangedComponent()
    {
        var original = new[] { "guid-x", "vol-y", "mac-z" };
        var token = DeviceFingerprint.Hash(original);
        var changedMac = new[] { "guid-x", "vol-y", "mac-DIFFERENT" };
        Assert.True(DeviceFingerprint.Matches(token, changedMac, minAgree: 2));
    }

    [Fact]
    public void Matches_ChangedComponentValue_NeverMatches_RegardlessOfMinAgree()
    {
        // Corrects the false premise of the skipped test above: a REPLACED component
        // value can never be tolerated by this hash-based scheme, at any minAgree.
        var original = new[] { "guid-x", "vol-y", "mac-z" };
        var token = DeviceFingerprint.Hash(original);
        var changedMac = new[] { "guid-x", "vol-y", "mac-DIFFERENT" };

        Assert.False(DeviceFingerprint.Matches(token, changedMac, minAgree: 1));
        Assert.False(DeviceFingerprint.Matches(token, changedMac, minAgree: 2));
        Assert.False(DeviceFingerprint.Matches(token, changedMac, minAgree: 3));
    }

    [Fact]
    public void Matches_TreatsNewlyAvailableComponent_AsCompatible()
    {
        // The one scenario the subset-matching mechanism genuinely supports: a
        // component that was unreadable at enrollment (so Hash() was computed over a
        // smaller set) and is readable now. The smaller original set is a
        // byte-identical subset of the larger current set, so its subset-hash still
        // equals the token.
        var original = new[] { "guid-x", "vol-y" }; // e.g. MAC unavailable at enrollment
        var token = DeviceFingerprint.Hash(original);

        var current = new[] { "guid-x", "vol-y", "mac-z" }; // MAC now available too
        Assert.True(DeviceFingerprint.Matches(token, current, minAgree: 2));
    }

    [Fact]
    public void Matches_CompletelyDifferentComponents_DoesNotMatch()
    {
        var original = new[] { "guid-x", "vol-y", "mac-z" };
        var token = DeviceFingerprint.Hash(original);
        var different = new[] { "guid-A", "vol-B", "mac-C" };
        Assert.False(DeviceFingerprint.Matches(token, different, minAgree: 2));
    }

    [Fact]
    public void Matches_MinAgreeEqualsLength_RequiresExactSet()
    {
        var original = new[] { "guid-x", "vol-y", "mac-z" };
        var token = DeviceFingerprint.Hash(original);

        // Exact same set (order independent) at minAgree == length -> matches; this is
        // the "all present" case the brief says degenerates to a direct hash compare.
        var reordered = new[] { "mac-z", "guid-x", "vol-y" };
        Assert.True(DeviceFingerprint.Matches(token, reordered, minAgree: 3));

        // One component changed at minAgree == length -> must NOT match.
        var oneChanged = new[] { "guid-x", "vol-y", "mac-DIFFERENT" };
        Assert.False(DeviceFingerprint.Matches(token, oneChanged, minAgree: 3));
    }

    [Fact]
    public void Matches_MinAgreeLessThanLength_WithSeveralComponents_StressesCombinationsGenerator()
    {
        // Exercises the Combinations() enumerator across several sizes (C(5,5)..C(5,1))
        // to guard against off-by-one / infinite-loop regressions, while asserting the
        // mathematically-correct outcome: any value replacement -- one component or
        // several -- is never tolerated, regardless of how low minAgree is set, because
        // no subset of a value-changed current set can reproduce the original full-set
        // hash (see Matches_ChangedComponentValue_NeverMatches_RegardlessOfMinAgree).
        var original = new[] { "c1", "c2", "c3", "c4", "c5" };
        var token = DeviceFingerprint.Hash(original);

        var oneChanged = new[] { "c1", "c2", "c3", "c4", "CHANGED-5" };
        Assert.False(DeviceFingerprint.Matches(token, oneChanged, minAgree: 1));

        var allChanged = new[] { "A1", "A2", "A3", "A4", "A5" };
        Assert.False(DeviceFingerprint.Matches(token, allChanged, minAgree: 1));

        // Exact match still succeeds at every minAgree down to 1 (the size==length
        // subset -- itself -- is always tried first).
        Assert.True(DeviceFingerprint.Matches(token, original, minAgree: 1));
        Assert.True(DeviceFingerprint.Matches(token, original, minAgree: 5));
    }

    [Fact]
    public void Matches_TooFewPresentComponents_NeverMatches()
    {
        var original = new[] { "guid-x", "vol-y", "mac-z" };
        var token = DeviceFingerprint.Hash(original);

        // Only 1 component present but minAgree requires 3 -> for-loop never executes.
        Assert.False(DeviceFingerprint.Matches(token, new[] { "guid-x" }, minAgree: 3));
    }

    [Fact]
    public void Hash_SingleComponent_TestDevice_MatchesCommittedContinuityVector()
    {
        // Later tasks pass new[]{"TEST-DEVICE"} as a single component with minAgree:1.
        // The committed test vectors bind device = SHA-256("TEST-DEVICE") over the raw
        // UTF-8 bytes of "TEST-DEVICE" -- i.e. Hash of a single-element array must equal
        // that value directly (sorting/joining a single element is a no-op).
        var hash = DeviceFingerprint.Hash(new[] { "TEST-DEVICE" });
        Assert.Equal("6be0412a5dac0a63d688a9a60608b2257c8292bb663738b952b9bbe5a4ff9fdd", hash);
    }

    [Fact]
    public void Matches_SingleComponent_TestDevice_MinAgreeOne()
    {
        var token = DeviceFingerprint.Hash(new[] { "TEST-DEVICE" });
        Assert.True(DeviceFingerprint.Matches(token, new[] { "TEST-DEVICE" }, minAgree: 1));
    }
}
