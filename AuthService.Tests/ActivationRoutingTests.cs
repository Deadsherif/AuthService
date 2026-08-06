using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using AuthService.MVVM.ViewModel;
using AuthService.Services.Licensing;
using Xunit;

public class ActivationRoutingTests
{
    private static string ValidToken()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        var vectors = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/vectors.json"));
        foreach (var v in vectors.EnumerateArray())
            if (v.GetProperty("name").GetString() == "valid") return v.GetProperty("token").GetString();
        throw new Exception("valid vector missing");
    }

    private static AuthViewModel NewVm(string storePath) =>
        new AuthViewModel("Addin", "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8")
        {
            TokenStoreOverride = new LicenseStore(storePath),
            NowOverride = DateTimeOffset.FromUnixTimeSeconds(1_750_000_000),
            DeviceOverride = "TEST-DEVICE",
        };

    [Fact]
    public async Task RawToken_Activates()
    {
        var vm = NewVm(Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json"));
        vm.Code = ValidToken();
        await vm.ActivateAsync();
        Assert.Equal(AuthService.Services.SubscriptionService.SubscriptionStatus.Valid,
                     AuthService.Services.SubscriptionService.Status);
    }

    [Fact]
    public async Task FoFile_Activates()
    {
        var foPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".FO");
        File.WriteAllText(foPath, ValidToken());
        var vm = NewVm(Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json"));
        vm.Code = foPath;
        await vm.ActivateAsync();
        Assert.Equal(AuthService.Services.SubscriptionService.SubscriptionStatus.Valid,
                     AuthService.Services.SubscriptionService.Status);
    }

    [Fact]
    public async Task FoFile_Missing_FailsCleanly()
    {
        var vm = NewVm(Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json"));
        vm.Code = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".FO"); // does not exist
        await vm.ActivateAsync();
        Assert.Contains("file not found", vm.Status);
    }
}
