using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using AuthService;
using AuthService.Services;
using AuthService.Services.Licensing;
using Xunit;

public class BackgroundTimeValidationTests
{
    [Fact]
    public async Task LocalValidationReturnsBeforeOnlineCheck_ThenContradictionRevokes()
    {
        const string addinId = "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8";
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        var vectors = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/vectors.json"));
        string token = null;
        foreach (var vector in vectors.EnumerateArray())
            if (vector.GetProperty("name").GetString() == "valid") token = vector.GetProperty("token").GetString();

        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        var store = new LicenseStore(path);
        store.Write(new StoredLicense
        {
            Token = token,
            MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000)
        });

        var oldGateFactory = Auth.GateFactory;
        var oldNowProvider = Auth.NowProvider;
        var oldDeviceProvider = Auth.DeviceProvider;
        var oldOnlineTimeProvider = Auth.OnlineTimeProvider;
        var oldDelay = Auth.BackgroundCheckDelay;
        var releaseOnlineCheck = new TaskCompletionSource<DateTimeOffset?>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        try
        {
            Auth.GateFactory = _ => new LicenseGate(store);
            Auth.NowProvider = () => DateTimeOffset.FromUnixTimeSeconds(1_750_000_000);
            Auth.DeviceProvider = () => "TEST-DEVICE";
            Auth.OnlineTimeProvider = () => releaseOnlineCheck.Task;
            Auth.BackgroundCheckDelay = TimeSpan.Zero;

            using (var auth = new Auth("Addin", addinId, (Window)null))
            {
                var status = await auth.Validate();

                Assert.Equal(SubscriptionService.SubscriptionStatus.Valid, status);
                Assert.False(auth.IsRevoked);

                releaseOnlineCheck.SetResult(DateTimeOffset.FromUnixTimeSeconds(1_600_000_000));
                await Auth.GetBackgroundCheck(addinId);

                Assert.True(auth.IsRevoked);
                Assert.Equal(SubscriptionService.SubscriptionStatus.NotFound, SubscriptionService.Status);
                Assert.True(store.Read().IsRevoked);
                Assert.Equal(
                    GateStatus.Invalid,
                    new LicenseGate(store).Evaluate(
                        addinId,
                        "TEST-DEVICE",
                        DateTimeOffset.FromUnixTimeSeconds(1_750_000_001)));
            }
        }
        finally
        {
            releaseOnlineCheck.TrySetResult(null);
            await Auth.GetBackgroundCheck(addinId);
            Auth.GateFactory = oldGateFactory;
            Auth.NowProvider = oldNowProvider;
            Auth.DeviceProvider = oldDeviceProvider;
            Auth.OnlineTimeProvider = oldOnlineTimeProvider;
            Auth.BackgroundCheckDelay = oldDelay;
        }
    }
}
