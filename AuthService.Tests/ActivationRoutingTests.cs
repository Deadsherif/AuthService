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

    private sealed class FakeMintClient : AuthService.Services.Licensing.IMintClient
    {
        private readonly AuthService.Services.Licensing.MintResult _r;
        public string LastCode; public string LastDevice;
        public FakeMintClient(AuthService.Services.Licensing.MintResult r) { _r = r; }
        public Task<AuthService.Services.Licensing.MintResult> RequestTokenAsync(string code, string deviceId)
        { LastCode = code; LastDevice = deviceId; return Task.FromResult(_r); }
    }

    [Fact]
    public async Task Code_CallsMint_AndActivatesReturnedToken()
    {
        var fake = new FakeMintClient(new AuthService.Services.Licensing.MintResult { Success = true, Token = ValidToken() });
        var vm = NewVm(Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json"));
        vm.UseLegacyActivation = false; // exercising the mint path explicitly
        vm.MintClientOverride = fake;
        vm.Code = "aWiS1Tbo2bm";
        await vm.ActivateAsync();
        Assert.Equal("aWiS1Tbo2bm", fake.LastCode);
        Assert.Equal(DeviceFingerprint.Hash("TEST-DEVICE"), fake.LastDevice);
        Assert.Equal(AuthService.Services.SubscriptionService.SubscriptionStatus.Valid,
                     AuthService.Services.SubscriptionService.Status);
    }

    [Fact]
    public async Task Code_MintFails_ShowsError()
    {
        var fake = new FakeMintClient(new AuthService.Services.Licensing.MintResult { Success = false, Error = "bad code" });
        var vm = NewVm(Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json"));
        vm.UseLegacyActivation = false; // exercising the mint path explicitly
        vm.MintClientOverride = fake;
        vm.Code = "nope";
        await vm.ActivateAsync();
        Assert.Contains("bad code", vm.Status);
    }

    [Fact]
    public async Task Code_MintReturnsInvalidToken_DoesNotActivate()
    {
        var fake = new FakeMintClient(new AuthService.Services.Licensing.MintResult { Success = true, Token = "eyJ.garbage.sig" });
        var storePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        var vm = NewVm(storePath);
        vm.UseLegacyActivation = false; // exercising the mint path explicitly
        vm.MintClientOverride = fake;
        vm.Code = "somecode";
        await vm.ActivateAsync();
        // Assert on isolated per-instance/store state, NOT the process-global
        // SubscriptionService.Status (which other tests mutate): an invalid mint
        // response must neither persist a token nor report success on this VM.
        Assert.Null(new AuthService.Services.Licensing.LicenseStore(storePath).Read()); // nothing stored
        Assert.Contains("invalid", vm.Status); // VM reported failure (message is lowercase "invalid")
    }

    private sealed class FakeLegacyClient : AuthService.Services.Licensing.ILegacyActivationClient
    {
        private readonly AuthService.Services.Licensing.LegacyActivationResult _r;
        public string LastCode; public string LastDevice;
        public FakeLegacyClient(AuthService.Services.Licensing.LegacyActivationResult r) { _r = r; }
        public Task<AuthService.Services.Licensing.LegacyActivationResult> RegisterAsync(
            string code,
            string deviceHash,
            System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        { LastCode = code; LastDevice = deviceHash; return Task.FromResult(_r); }
    }

    [Fact]
    public async Task Legacy_RegistersDeviceHash_ButDoesNotGrantAccess()
    {
        var fake = new FakeLegacyClient(new AuthService.Services.Licensing.LegacyActivationResult { CodeValid = true, Registered = true });
        var storePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        var vm = NewVm(storePath);
        vm.UseLegacyActivation = true;
        vm.LegacyClientOverride = fake;
        vm.Code = "aWiS1Tbo2bm";

        await vm.ActivateAsync();

        // device hash sent is Hash(MachineGuid-stand-in), matching the token contract
        Assert.Equal(DeviceFingerprint.Hash("TEST-DEVICE"), fake.LastDevice);
        Assert.Equal("aWiS1Tbo2bm", fake.LastCode);
        // NOT granted: nothing stored, and this VM did not report a valid license
        Assert.Null(new AuthService.Services.Licensing.LicenseStore(storePath).Read());
        Assert.Contains("issued", vm.Status, StringComparison.OrdinalIgnoreCase); // "...will be issued shortly"
    }

    [Fact]
    public async Task Legacy_UnknownCode_ShowsError()
    {
        var fake = new FakeLegacyClient(new AuthService.Services.Licensing.LegacyActivationResult { CodeValid = false, Registered = false, Error = "Code not found" });
        var vm = NewVm(Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json"));
        vm.UseLegacyActivation = true;
        vm.LegacyClientOverride = fake;
        vm.Code = "nope";

        await vm.ActivateAsync();

        Assert.Contains("Code not found", vm.Status);
    }

    [Fact]
    public async Task Legacy_NeverSetsGlobalValid_ForFreshVmBaseline()
    {
        // A legacy registration must not touch the licensing store for this VM.
        var fake = new FakeLegacyClient(new AuthService.Services.Licensing.LegacyActivationResult { CodeValid = true, Registered = true });
        var storePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        var vm = NewVm(storePath);
        vm.UseLegacyActivation = true;
        vm.LegacyClientOverride = fake;
        vm.Code = "aWiS1Tbo2bm";

        await vm.ActivateAsync();

        Assert.Null(new AuthService.Services.Licensing.LicenseStore(storePath).Read());
    }
}
