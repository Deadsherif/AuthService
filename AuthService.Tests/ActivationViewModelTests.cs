using System;
using System.IO;
using System.Text.Json;
using AuthService.MVVM.ViewModel;
using AuthService.Services.Licensing;
using Xunit;

public class ActivationViewModelTests
{
    [Fact]
    public void PasteValidToken_Activates()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        var vectors = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/vectors.json"));
        string token = null;
        foreach (var v in vectors.EnumerateArray())
            if (v.GetProperty("name").GetString() == "valid") token = v.GetProperty("token").GetString();

        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        var vm = new AuthViewModel("Addin", "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8")
        {
            TokenStoreOverride = new LicenseStore(path),
            NowOverride = DateTimeOffset.FromUnixTimeSeconds(1_750_000_000),
            DeviceOverride = "TEST-DEVICE",
            PastedToken = token
        };

        vm.ActivateTokenCommand.Execute(null);

        Assert.Equal(AuthService.Services.SubscriptionService.SubscriptionStatus.Valid,
                     AuthService.Services.SubscriptionService.Status);
    }

    // iat floor: NowOverride (1_650_000_000) is below the valid vector's iat (1_700_000_000).
    // The stored MaxDateSeen must be seeded with the later of the two -- the token's iat --
    // not just "now", so LicenseGate's anti-rollback ratchet starts at the correct floor.
    [Fact]
    public void PasteValidToken_SeedsIatFloor_NotJustNow()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        var vectors = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/vectors.json"));
        string token = null;
        foreach (var v in vectors.EnumerateArray())
            if (v.GetProperty("name").GetString() == "valid") token = v.GetProperty("token").GetString();

        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        var store = new LicenseStore(path);
        var iat = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000); // valid vector's iat
        var now = DateTimeOffset.FromUnixTimeSeconds(1_650_000_000); // deliberately before iat

        var vm = new AuthViewModel("Addin", "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8")
        {
            TokenStoreOverride = store,
            NowOverride = now,
            DeviceOverride = "TEST-DEVICE",
            PastedToken = token
        };

        vm.ActivateTokenCommand.Execute(null);

        Assert.Equal(AuthService.Services.SubscriptionService.SubscriptionStatus.Valid,
                     AuthService.Services.SubscriptionService.Status);

        var stored = store.Read();
        Assert.NotNull(stored);
        Assert.Equal(iat, stored.MaxDateSeen);
    }

    // A verified, unexpired token minted for a different device must not activate this
    // machine -- the addon may be right and the signature valid, but the device claim
    // (SHA-256 hash of the device id) does not match this VM's DeviceOverride.
    [Fact]
    public void PasteWrongDeviceToken_IsRejected()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        var vectors = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/vectors.json"));
        string token = null;
        foreach (var v in vectors.EnumerateArray())
            if (v.GetProperty("name").GetString() == "wrongDevice") token = v.GetProperty("token").GetString();

        AuthService.Services.SubscriptionService.SetStatus(AuthService.Services.SubscriptionService.SubscriptionStatus.Error);

        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        var store = new LicenseStore(path);

        var vm = new AuthViewModel("Addin", "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8")
        {
            TokenStoreOverride = store,
            NowOverride = DateTimeOffset.FromUnixTimeSeconds(1_750_000_000),
            DeviceOverride = "TEST-DEVICE",
            PastedToken = token
        };

        vm.ActivateTokenCommand.Execute(null);

        Assert.NotEqual(AuthService.Services.SubscriptionService.SubscriptionStatus.Valid,
                         AuthService.Services.SubscriptionService.Status);
        Assert.Null(store.Read());
    }
}
