using System;
using System.Text.Json;
using AuthService.Services.Licensing;
using Xunit;

public class LicenseTokenVerifierTests
{
    private static void LoadKey()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(System.IO.File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
    }

    [Theory]
    [InlineData("valid", VerifyStatus.Valid)]
    [InlineData("tampered", VerifyStatus.BadSignature)]
    [InlineData("expired", VerifyStatus.Expired)]
    [InlineData("wrongKey", VerifyStatus.BadSignature)]
    public void Verify_MatchesVectorExpectation(string name, VerifyStatus expected)
    {
        LoadKey();
        var vectors = JsonSerializer.Deserialize<JsonElement>(System.IO.File.ReadAllText("Vectors/vectors.json"));
        string token = null;
        foreach (var v in vectors.EnumerateArray())
            if (v.GetProperty("name").GetString() == name) token = v.GetProperty("token").GetString();

        var now = DateTimeOffset.FromUnixTimeSeconds(1_750_000_000); // between iat and far exp
        var result = new LicenseTokenVerifier().Verify(token, now);
        Assert.Equal(expected, result.Status);
    }
}
