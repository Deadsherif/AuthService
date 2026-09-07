using System;
using System.IO;
using System.Reflection;
using AuthService.Services.Licensing;
using Xunit;

public class LicenseStoreTests
{
    [Fact]
    public void DefaultStore_IsDifferentForEachAddin()
    {
        var first = LicenseStore.Default("11111111-1111-1111-1111-111111111111");
        var second = LicenseStore.Default("22222222-2222-2222-2222-222222222222");
        var pathField = typeof(LicenseStore).GetField("_path", BindingFlags.Instance | BindingFlags.NonPublic);

        var firstPath = (string)pathField.GetValue(first);
        var secondPath = (string)pathField.GetValue(second);

        Assert.NotEqual(firstPath, secondPath);
        Assert.EndsWith(Path.Combine("11111111-1111-1111-1111-111111111111", "license.json"), firstPath);
        Assert.EndsWith(Path.Combine("22222222-2222-2222-2222-222222222222", "license.json"), secondPath);
    }

    [Fact]
    public void RoundTripsTokenAndRatchet()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        var store = new LicenseStore(path);
        store.Write(new StoredLicense { Token = "abc.def.ghi", MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_750_000_000) });
        var back = store.Read();
        Assert.Equal("abc.def.ghi", back.Token);
        Assert.Equal(1_750_000_000, back.MaxDateSeen.ToUnixTimeSeconds());
        store.Clear();
        Assert.Null(store.Read());
    }
}
