using System.Text.Json;
using AuthService.Services.Licensing;
using Xunit;

public class LicensePublicKeysTests
{
    [Fact]
    public void Resolve_KnownKid_ReturnsKey()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(System.IO.File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        Assert.NotNull(LicensePublicKeys.Resolve("k1"));
        Assert.Null(LicensePublicKeys.Resolve("nope"));
    }
}
