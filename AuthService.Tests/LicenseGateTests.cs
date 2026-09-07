using System;
using System.IO;
using System.Text.Json;
using AuthService.Services.Licensing;
using Xunit;

public class LicenseGateTests
{
    [Fact]
    public void ValidToken_MatchingDevice_Passes()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        var vectors = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/vectors.json"));
        string token = null;
        foreach (var v in vectors.EnumerateArray())
            if (v.GetProperty("name").GetString() == "valid") token = v.GetProperty("token").GetString();

        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        new LicenseStore(path).Write(new StoredLicense { Token = token, MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000) });

        // vector device hash == SHA256("TEST-DEVICE"); pass that exact single component
        var gate = new LicenseGate(new LicenseStore(path));
        var status = gate.Evaluate(
            "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8",
            "TEST-DEVICE",
            DateTimeOffset.FromUnixTimeSeconds(1_750_000_000));

        Assert.Equal(GateStatus.Valid, status);
    }

    [Fact]
    public void RolledBackClock_IsRejected()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        new LicenseStore(path).Write(new StoredLicense { Token = "x", MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000) });
        var gate = new LicenseGate(new LicenseStore(path));
        Assert.Equal(GateStatus.Rollback, gate.Evaluate("any", "TEST-DEVICE", DateTimeOffset.FromUnixTimeSeconds(1_700_000_000)));
    }

    [Fact]
    public void WrongDevice_IsRejected()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        var vectors = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/vectors.json"));
        string token = null;
        foreach (var v in vectors.EnumerateArray())
            if (v.GetProperty("name").GetString() == "valid") token = v.GetProperty("token").GetString();
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        new LicenseStore(path).Write(new StoredLicense { Token = token, MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000) });
        var gate = new LicenseGate(new LicenseStore(path));
        Assert.Equal(GateStatus.Invalid, gate.Evaluate(
            "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8", "SOME-OTHER-MACHINE", DateTimeOffset.FromUnixTimeSeconds(1_750_000_000)));
    }

    // iat floor: MaxDateSeen (1.68e9) is below the token's iat (1.70e9). A clock at 1.69e9
    // is above MaxDateSeen but below the iat floor → Rollback. (valid vector: iat=1_700_000_000)
    [Fact]
    public void ClockBelowIatFloor_IsRollback()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        var vectors = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/vectors.json"));
        string token = null;
        foreach (var v in vectors.EnumerateArray())
            if (v.GetProperty("name").GetString() == "valid") token = v.GetProperty("token").GetString();
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        new LicenseStore(path).Write(new StoredLicense { Token = token, MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_680_000_000) });
        var gate = new LicenseGate(new LicenseStore(path));
        Assert.Equal(GateStatus.Rollback, gate.Evaluate(
            "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8", "TEST-DEVICE", DateTimeOffset.FromUnixTimeSeconds(1_690_000_000)));
    }

    // Expiry is decided against the ratchet max: an honest clock past exp rejects the token.
    // (valid vector: exp=1_900_000_000)
    [Fact]
    public void PastExpiry_IsInvalid()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        var vectors = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/vectors.json"));
        string token = null;
        foreach (var v in vectors.EnumerateArray())
            if (v.GetProperty("name").GetString() == "valid") token = v.GetProperty("token").GetString();
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        new LicenseStore(path).Write(new StoredLicense { Token = token, MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000) });
        var gate = new LicenseGate(new LicenseStore(path));
        Assert.Equal(GateStatus.Invalid, gate.Evaluate(
            "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8", "TEST-DEVICE", DateTimeOffset.FromUnixTimeSeconds(2_000_000_000)));
    }

    // A token whose signature does not verify must fail closed through the gate itself, not
    // just at the verifier layer: exercises the "!= Valid && != Expired -> Invalid" branch.
    [Fact]
    public void BadSignatureToken_IsInvalid()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        var vectors = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/vectors.json"));
        string token = null;
        foreach (var v in vectors.EnumerateArray())
            if (v.GetProperty("name").GetString() == "tampered") token = v.GetProperty("token").GetString();
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        new LicenseStore(path).Write(new StoredLicense { Token = token, MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000) });
        var gate = new LicenseGate(new LicenseStore(path));
        Assert.Equal(GateStatus.Invalid, gate.Evaluate(
            "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8", "TEST-DEVICE", DateTimeOffset.FromUnixTimeSeconds(1_750_000_000)));
    }

    // A verified, unexpired token for the wrong add-in must still be rejected by the gate.
    [Fact]
    public void AddonMismatch_IsInvalid()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        var vectors = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/vectors.json"));
        string token = null;
        foreach (var v in vectors.EnumerateArray())
            if (v.GetProperty("name").GetString() == "valid") token = v.GetProperty("token").GetString();
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        new LicenseStore(path).Write(new StoredLicense { Token = token, MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000) });
        var gate = new LicenseGate(new LicenseStore(path));
        Assert.Equal(GateStatus.Invalid, gate.Evaluate(
            "00000000-0000-0000-0000-000000000000", "TEST-DEVICE", DateTimeOffset.FromUnixTimeSeconds(1_750_000_000)));
    }

    // A bogus/attacker-controlled future online reading (still < exp) must be able to pass
    // the token as Valid (expiry check may use it) but must NEVER be persisted into the
    // ratchet — only the local clock (and iat) may advance MaxDateSeen. Otherwise a single
    // bad online reading would permanently self-lock every future honest run.
    [Fact]
    public void BogusFutureOnline_NotPersistedToRatchet()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        var vectors = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/vectors.json"));
        string token = null;
        foreach (var v in vectors.EnumerateArray())
            if (v.GetProperty("name").GetString() == "valid") token = v.GetProperty("token").GetString();
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        var store = new LicenseStore(path);
        store.Write(new StoredLicense { Token = token, MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000) });
        var gate = new LicenseGate(store);

        var status = gate.Evaluate(
            "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8",
            "TEST-DEVICE",
            DateTimeOffset.FromUnixTimeSeconds(1_750_000_000),
            DateTimeOffset.FromUnixTimeSeconds(1_850_000_000)); // bogus future online, but < exp 1_900_000_000

        Assert.Equal(GateStatus.Valid, status);
        Assert.Equal(1_750_000_000, store.Read().MaxDateSeen.ToUnixTimeSeconds()); // NOT 1_850_000_000
    }

    // Online time may still detect an expired token even when the local clock has been
    // rolled back to look fine (but not below MaxDateSeen, so it isn't rejected as Rollback).
    [Fact]
    public void OnlineDetectsExpiry_WithRolledBackClock()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        var vectors = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/vectors.json"));
        string token = null;
        foreach (var v in vectors.EnumerateArray())
            if (v.GetProperty("name").GetString() == "valid") token = v.GetProperty("token").GetString();
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        var store = new LicenseStore(path);
        store.Write(new StoredLicense { Token = token, MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000) });
        var gate = new LicenseGate(store);

        var status = gate.Evaluate(
            "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8",
            "TEST-DEVICE",
            DateTimeOffset.FromUnixTimeSeconds(1_700_000_001), // local clock, rolled back but still >= MaxDateSeen
            DateTimeOffset.FromUnixTimeSeconds(2_000_000_000)); // honest online reading, past exp 1_900_000_000

        Assert.Equal(GateStatus.Invalid, status);
    }

    [Fact]
    public void OnlineDateBeforeRatchet_IsTimeContradiction()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        var vectors = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/vectors.json"));
        string token = null;
        foreach (var v in vectors.EnumerateArray())
            if (v.GetProperty("name").GetString() == "valid") token = v.GetProperty("token").GetString();

        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        var store = new LicenseStore(path);
        store.Write(new StoredLicense
        {
            Token = token,
            MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_750_000_000)
        });

        var status = new LicenseGate(store).Evaluate(
            "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8",
            "TEST-DEVICE",
            DateTimeOffset.FromUnixTimeSeconds(1_750_000_001),
            DateTimeOffset.FromUnixTimeSeconds(1_700_000_000));

        Assert.Equal(GateStatus.TimeContradiction, status);
    }
}
