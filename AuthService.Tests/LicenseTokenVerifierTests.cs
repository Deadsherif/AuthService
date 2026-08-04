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

    [Fact]
    public void Verify_GarbageString_ReturnsMalformed()
    {
        var result = new LicenseTokenVerifier().Verify("not.a.jwt", DateTimeOffset.UtcNow);
        Assert.Equal(VerifyStatus.Malformed, result.Status);
    }

    [Fact]
    public void Verify_UnknownKid_ReturnsUnknownKey()
    {
        // Build a syntactically valid ES256 JWT whose "kid" was never loaded into
        // LicensePublicKeys. This deliberately avoids relying on "k1" being unloaded:
        // LicensePublicKeys is a static store shared across tests in this class, so another
        // test may have already called LoadKey() by the time this one runs. A kid that has
        // never been (and will never be) loaded by any test keeps this assertion independent
        // of xUnit's test-execution order.
        var header = new { alg = "ES256", kid = "never-loaded-" + Guid.NewGuid().ToString("N"), typ = "JWT" };
        var headerB64 = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(header));

        // The payload/signature content is irrelevant here: Verify() resolves the signing key
        // from the header's kid and returns UnknownKey before any signature validation is
        // attempted, so this never needs to be signed by a real key.
        var payloadB64 = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(new { }));
        var token = $"{headerB64}.{payloadB64}.sig";

        var result = new LicenseTokenVerifier().Verify(token, DateTimeOffset.UtcNow);
        Assert.Equal(VerifyStatus.UnknownKey, result.Status);
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
