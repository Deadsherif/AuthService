using System;
using System.IO;
using System.Text.Json;
using AuthService;
using AuthService.Services;
using AuthService.Services.Licensing;
using Xunit;

public class OnlineTimeAnchorTests
{
    [Fact]
    public void OnlineTime_AnchorsRatchetForward()
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
        Auth.OnlineTimeProvider = () => DateTimeOffset.FromUnixTimeSeconds(1_800_000_000); // higher trusted reading (< exp 1.9e9)
        Auth.DeviceProvider = () => "TEST-DEVICE";

        var status = Auth.ValidateAuth("Addin", "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8").GetAwaiter().GetResult();
        Assert.Equal(SubscriptionService.SubscriptionStatus.Valid, status);
        Assert.Equal(1_800_000_000, store.Read().MaxDateSeen.ToUnixTimeSeconds()); // anchored to online time, not local 1.76e9
    }
}
