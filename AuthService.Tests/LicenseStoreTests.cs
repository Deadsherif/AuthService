using System;
using System.IO;
using AuthService.Services.Licensing;
using Xunit;

public class LicenseStoreTests
{
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
