using AuthService.Services.Licensing;
using Xunit;

public class DeviceFingerprintTests
{
    [Fact]
    public void Hash_OfTestDevice_MatchesCommittedVector()
    {
        Assert.Equal(
            "6be0412a5dac0a63d688a9a60608b2257c8292bb663738b952b9bbe5a4ff9fdd",
            DeviceFingerprint.Hash("TEST-DEVICE"));
    }

    [Fact]
    public void Matches_SameId_True_DifferentId_False()
    {
        var token = DeviceFingerprint.Hash("machine-guid-abc");
        Assert.True(DeviceFingerprint.Matches(token, "machine-guid-abc"));
        Assert.False(DeviceFingerprint.Matches(token, "machine-guid-XYZ"));
    }

    [Fact]
    public void Matches_NullOrEmptyCurrentId_False()
    {
        var token = DeviceFingerprint.Hash("machine-guid-abc");
        Assert.False(DeviceFingerprint.Matches(token, null));
        Assert.False(DeviceFingerprint.Matches(token, ""));
    }
}
