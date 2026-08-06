using AuthService.Services.Licensing;
using Xunit;

public class OfflineActivationClientParityTests
{
    [Fact]
    public void Sha256Hex_MatchesDeviceFingerprintHash()
    {
        // Both must produce the identical device value for the same input, or an
        // offline-minted token will never match the add-in's computed device id.
        Assert.Equal(
            DeviceFingerprint.Hash("TEST-DEVICE"),
            OfflineActivationClient.DeviceId.Sha256Hex("TEST-DEVICE"));

        Assert.Equal(
            "6be0412a5dac0a63d688a9a60608b2257c8292bb663738b952b9bbe5a4ff9fdd",
            OfflineActivationClient.DeviceId.Sha256Hex("TEST-DEVICE"));
    }
}
