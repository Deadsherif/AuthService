using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using AuthService;
using AuthService.Services;
using AuthService.Services.Licensing;
using Xunit;

public class AuthValidateTests
{
    [Fact]
    public async Task StoredValidToken_ReturnsValid_NoUi()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        var vectors = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/vectors.json"));
        string token = null;
        foreach (var v in vectors.EnumerateArray())
            if (v.GetProperty("name").GetString() == "valid") token = v.GetProperty("token").GetString();

        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        new LicenseStore(path).Write(new StoredLicense { Token = token, MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000) });

        Auth.GateFactory = _ => new LicenseGate(new LicenseStore(path));
        Auth.NowProvider = () => DateTimeOffset.FromUnixTimeSeconds(1_750_000_000);
        Auth.DeviceProvider = () => "TEST-DEVICE";

        var status = await Auth.ValidateAuth("Addin", "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8");
        Assert.Equal(SubscriptionService.SubscriptionStatus.Valid, status);
    }
}
