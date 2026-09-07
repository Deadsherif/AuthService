using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using AuthService;
using AuthService.Services;
using AuthService.Services.Licensing;
using Xunit;

public class OnlineTimeAnchorTests
{
    // Online time is used for expiry DETECTION only and must never be persisted into the
    // anti-rollback ratchet. A higher online reading must not anchor MaxDateSeen forward past
    // the local clock — otherwise a single bogus/future online reading would permanently
    // self-lock every later honest run (now < MaxDateSeen -> Rollback forever).
    [Fact]
    public async Task OnlineTime_DetectsButDoesNotPersistToRatchet()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        var vectors = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/vectors.json"));
        string token = null;
        foreach (var v in vectors.EnumerateArray())
            if (v.GetProperty("name").GetString() == "valid") token = v.GetProperty("token").GetString();

        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        var store = new LicenseStore(path);
        store.Write(new StoredLicense { Token = token, MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_750_000_000) });

        Auth.GateFactory = _ => new LicenseGate(new LicenseStore(path));
        Auth.NowProvider = () => DateTimeOffset.FromUnixTimeSeconds(1_760_000_000);      // local clock
        Auth.OnlineTimeProvider = () => Task.FromResult<DateTimeOffset?>(
            DateTimeOffset.FromUnixTimeSeconds(1_800_000_000)); // higher online reading (< exp 1.9e9)
        Auth.DeviceProvider = () => "TEST-DEVICE";

        var status = await Auth.ValidateAuth("Addin", "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8");
        await Auth.GetBackgroundCheck("9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8");
        Assert.Equal(SubscriptionService.SubscriptionStatus.Valid, status);
        Assert.Equal(1_760_000_000, store.Read().MaxDateSeen.ToUnixTimeSeconds()); // reflects LOCAL clock, not online 1.8e9
    }
}
