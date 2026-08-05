using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthService.Services.Licensing;
using Microsoft.IdentityModel.Tokens;
using Xunit;

// End-to-end smoke test over the *whole* pipeline: mint a fresh token in-test with a
// throwaway ECDSA P-256 key (mirrors tools/LicenseMint/Program.cs's Mint()), register the
// public half via LicensePublicKeys.LoadForTests, seed a LicenseStore, and drive it through
// LicenseGate.Evaluate exactly as the shipped client would. This is not a unit test of any
// one component -- every other test file already covers those in isolation -- it exists to
// catch integration seams the unit tests can't see (wrong claim names, wrong key encoding,
// wrong verifier wiring) by exercising the real components together.
//
// Uses a unique kid ("e2e-k1") rather than the "k1" used by Vectors/keys.json and the other
// test files: LicensePublicKeys is a static, process-wide store, and DisableTestParallelization
// is set assembly-wide (see TestCollectionSetup.cs) specifically because shared static state
// cannot tolerate interleaved/racing writers. A distinct kid keeps this test's key material
// from colliding with (or being collided into by) any other test, independent of run order.
public class EndToEndSmokeTests
{
    private const string Kid = "e2e-k1";
    private const string AddinId = "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8";
    private const string DeviceId = "E2E-DEVICE";

    [Fact]
    public void FullPipeline_ValidToken_GateReturnsValid()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        LicensePublicKeys.LoadForTests(Kid, ec.ExportSubjectPublicKeyInfoPem());

        var now = DateTimeOffset.FromUnixTimeSeconds(1_750_000_000);
        var iat = now.AddSeconds(-3600);
        var exp = now.AddDays(30);

        string token = Mint(ec, iat, exp, DeviceFingerprint.Hash(DeviceId));

        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        new LicenseStore(path).Write(new StoredLicense { Token = token, MaxDateSeen = iat });

        var gate = new LicenseGate(new LicenseStore(path));
        var status = gate.Evaluate(AddinId, DeviceId, now);

        Assert.Equal(GateStatus.Valid, status);
    }

    [Fact]
    public void FullPipeline_TamperedToken_NotValid()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        LicensePublicKeys.LoadForTests(Kid, ec.ExportSubjectPublicKeyInfoPem());

        var now = DateTimeOffset.FromUnixTimeSeconds(1_750_000_000);
        var iat = now.AddSeconds(-3600);
        var exp = now.AddDays(30);

        string token = Mint(ec, iat, exp, DeviceFingerprint.Hash(DeviceId));
        string tampered = FlipOnePayloadChar(token);

        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        new LicenseStore(path).Write(new StoredLicense { Token = tampered, MaxDateSeen = iat });

        var gate = new LicenseGate(new LicenseStore(path));
        var status = gate.Evaluate(AddinId, DeviceId, now);

        // Confirmed by construction: a corrupted payload byte breaks the ES256 signature,
        // so the verifier reports BadSignature and the gate maps that to Invalid (not
        // Rollback, not Valid). Asserting the exact status here (rather than just
        // NotEqual(Valid)) pins that behavior.
        Assert.Equal(GateStatus.Invalid, status);
    }

    // Mirrors tools/LicenseMint/Program.cs's Mint(): same claim set, same signing-key setup
    // (CacheSignatureProviders = false so distinct throwaway ECDsa instances sharing a kid
    // across tests never resolve a stale/disposed cached provider).
    private static string Mint(ECDsa ec, DateTimeOffset iat, DateTimeOffset exp, string deviceHash)
    {
        var key = new ECDsaSecurityKey(ec) { KeyId = Kid };
        key.CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false };
        var creds = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256);

        var token = new JwtSecurityToken(
            claims: new[]
            {
                new Claim("iss", "firstoption"),
                new Claim("addon", AddinId),
                new Claim("tier", "paid"),
                new Claim("iat", iat.ToUnixTimeSeconds().ToString()),
                new Claim("exp", exp.ToUnixTimeSeconds().ToString()),
                new Claim("device", deviceHash),
                new Claim("jti", Guid.NewGuid().ToString()),
            },
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    // Flips one character in the middle of the payload (2nd, base64url) segment, then
    // re-encodes the segments unchanged. This breaks the signature (BadSignature at the
    // verifier), which is exactly the "tamper-evident, not encrypted" property Part 1 of the
    // design relies on: the gate must fail closed on any payload edit.
    private static string FlipOnePayloadChar(string jwt)
    {
        var parts = jwt.Split('.');
        var payload = parts[1];
        var chars = payload.ToCharArray();
        var mid = chars.Length / 2;
        chars[mid] = chars[mid] == 'A' ? 'B' : 'A';
        parts[1] = new string(chars);
        return string.Join('.', parts);
    }
}
