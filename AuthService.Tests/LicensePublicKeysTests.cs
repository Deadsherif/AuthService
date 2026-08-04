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

    [Fact]
    public void Resolve_GarbagePem_ReturnsNull()
    {
        LicensePublicKeys.LoadForTests("bad", "not-a-pem");
        Assert.Null(LicensePublicKeys.Resolve("bad"));
    }

    [Fact]
    public void Resolve_TruncatedDer_ReturnsNull()
    {
        // Valid PEM armor wrapped around a base64 body that decodes to only a few DER bytes -
        // nowhere near a complete SubjectPublicKeyInfo structure.
        const string pem = "-----BEGIN PUBLIC KEY-----\nMFk=\n-----END PUBLIC KEY-----";
        LicensePublicKeys.LoadForTests("truncated", pem);
        Assert.Null(LicensePublicKeys.Resolve("truncated"));
    }

    [Fact]
    public void Resolve_WrongCurveOid_ReturnsNull()
    {
        // A genuine SubjectPublicKeyInfo PEM for a secp256k1 key (same-shape uncompressed
        // point: 0x04 || 32-byte X || 32-byte Y, so the point-length check alone would not
        // catch this) - the named-curve OID differs from prime256v1 (1.2.840.10045.3.1.7)
        // and must be rejected rather than force-fit into nistP256.
        const string secp256k1Pem =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEM2jbxzYpvwg4cbqmcFoxTmc0PEex4u7e\n" +
            "1uBJuX1ndqNqEa2ZgqizzR7bfHd81/X8GL9wddCyPAFYCL+CaZoLYw==\n" +
            "-----END PUBLIC KEY-----";
        LicensePublicKeys.LoadForTests("wrongcurve", secp256k1Pem);
        Assert.Null(LicensePublicKeys.Resolve("wrongcurve"));
    }
}
