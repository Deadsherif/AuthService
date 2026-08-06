using AuthService.Services.Licensing;
using Xunit;

public class OfflineActivationClientParityTests
{
    [Fact]
    public void Anchor_ExactValue_TestDevice()
    {
        // Pin the exact expected value for "TEST-DEVICE" to catch any future drift
        // in the SHA256 implementation or input processing.
        Assert.Equal(
            "6be0412a5dac0a63d688a9a60608b2257c8292bb663738b952b9bbe5a4ff9fdd",
            OfflineActivationClient.DeviceId.Sha256Hex("TEST-DEVICE"));
    }

    [Theory]
    [InlineData("TEST-DEVICE")]
    [InlineData("")]
    [InlineData("12345678-90ab-cdef-1234-567890abcdef")]
    [InlineData("Ünïçödé-Ømega-测试")]
    [InlineData("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")]
    public void Sha256Hex_MatchesDeviceFingerprintHash(string input)
    {
        // Both add-in and standalone tool must produce identical device IDs for the same input,
        // or an offline-minted token will never match the add-in's computed device id.
        // Test across representative inputs: test sentinel, empty string, GUID format, Unicode, and long strings.
        Assert.Equal(
            DeviceFingerprint.Hash(input),
            OfflineActivationClient.DeviceId.Sha256Hex(input));
    }
}
