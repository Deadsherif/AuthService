using System.Security.Cryptography;
using System.Text.Json;

if (args.Length == 0) { Console.WriteLine("verbs: keygen | mint | vectors"); return 0; }

switch (args[0])
{
    case "keygen":
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keys = new
        {
            kid = "k1",
            publicKeyPem = ec.ExportSubjectPublicKeyInfoPem(),
            privateKeyPem = ec.ExportPkcs8PrivateKeyPem()
        };
        File.WriteAllText("keys.json", JsonSerializer.Serialize(keys, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine("wrote keys.json");
        return 0;
    }

    case "mint":
    {
        // mint <privateKeyPemPath> <kid> <addon> <tier> <iat> <exp> <deviceFilePath>
        if (args.Length < 8)
        {
            Console.WriteLine("usage: mint <privateKeyPemPath> <kid> <addon> <tier> <iat> <exp> <deviceFilePath>");
            return 1;
        }
        string privPem = File.ReadAllText(args[1]);
        string kid = args[2];
        string addon = args[3];
        string tier = args[4];
        long iat = long.Parse(args[5]);
        long exp = long.Parse(args[6]);

        // The device value is read from a file (produced by OfflineActivationClient):
        // first non-empty, trimmed line is the SHA-256(MachineGuid) hex device id.
        string deviceFile = args[7];
        if (!File.Exists(deviceFile))
        {
            Console.WriteLine($"device file not found: {deviceFile}");
            return 1;
        }
        string device = null;
        foreach (var line in File.ReadAllLines(deviceFile))
        {
            var t = line.Trim();
            if (t.Length > 0) { device = t; break; }
        }
        if (string.IsNullOrEmpty(device))
        {
            Console.WriteLine($"device file is empty: {deviceFile}");
            return 1;
        }

        string token = Mint(privPem, kid, addon, tier, iat, exp, device);
        Console.WriteLine(token);
        return 0;
    }

    case "vectors":
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("keys.json"));
        string priv = keys.GetProperty("privateKeyPem").GetString();
        string kid  = keys.GetProperty("kid").GetString();
        string device = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("TEST-DEVICE"))).ToLowerInvariant();

        long iat = 1_700_000_000, farExp = 1_900_000_000, pastExp = 1_600_000_000;
        string addon = "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8";

        string good     = Mint(priv, kid, addon, "paid", iat, farExp, device);
        string expired  = Mint(priv, kid, addon, "paid", iat, pastExp, device);
        string wrongDev = Mint(priv, kid, addon, "paid", iat, farExp, "deadbeef");
        string tampered = Tamper(good);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string wrongKey = Mint(other.ExportPkcs8PrivateKeyPem(), kid, addon, "paid", iat, farExp, device);

        var vectors = new[]
        {
            new { name = "valid",      token = good,     expectValid = true,  reason = "well-formed" },
            new { name = "tampered",   token = tampered, expectValid = false, reason = "payload edited" },
            new { name = "expired",    token = expired,  expectValid = false, reason = "exp in past" },
            new { name = "wrongDevice",token = wrongDev, expectValid = false, reason = "device mismatch" },
            new { name = "wrongKey",   token = wrongKey, expectValid = false, reason = "unknown signer" },
        };
        File.WriteAllText("vectors.json", JsonSerializer.Serialize(vectors, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine("wrote vectors.json");
        return 0;
    }
}
return 0;

static string Mint(string privPem, string kid, string addon, string tier, long iat, long exp, string device)
{
    using var ec = ECDsa.Create();
    ec.ImportFromPem(privPem);
    var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
    var key = new Microsoft.IdentityModel.Tokens.ECDsaSecurityKey(ec) { KeyId = kid };
    // Disable signature-provider caching: repeated Mint() calls reuse the same
    // KeyId ("k1") across distinct, short-lived ECDsa instances. With caching on,
    // CryptoProviderFactory's cache (keyed by KeyId+algorithm) returns a stale
    // SignatureProvider wrapping an already-disposed ECDsa from a prior call,
    // causing ObjectDisposedException on ECDsaCng.SignHash.
    key.CryptoProviderFactory = new Microsoft.IdentityModel.Tokens.CryptoProviderFactory
    {
        CacheSignatureProviders = false
    };
    var creds = new Microsoft.IdentityModel.Tokens.SigningCredentials(
        key, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.EcdsaSha256);
    var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
        claims: new[]
        {
            new System.Security.Claims.Claim("iss", "firstoption"),
            new System.Security.Claims.Claim("addon", addon),
            new System.Security.Claims.Claim("tier", tier),
            new System.Security.Claims.Claim("iat", iat.ToString()),
            new System.Security.Claims.Claim("exp", exp.ToString()),
            new System.Security.Claims.Claim("device", device),
            new System.Security.Claims.Claim("jti", Guid.NewGuid().ToString()),
        },
        signingCredentials: creds);
    return new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(token);
}

static string Tamper(string jwt)
{
    var parts = jwt.Split('.');
    var payload = System.Text.Encoding.UTF8.GetString(Base64Url(parts[1]));
    payload = payload.Replace("\"paid\"", "\"enterprise\"");
    parts[1] = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(payload))
        .TrimEnd('=').Replace('+','-').Replace('/','_');
    return string.Join('.', parts);
}

static byte[] Base64Url(string s)
{
    s = s.Replace('-','+').Replace('_','/');
    switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; }
    return Convert.FromBase64String(s);
}
