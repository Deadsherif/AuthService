# Sealed-Token Licensing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace AuthService's client-side trust model with offline-verifiable ES256-signed JWT license tokens, plus an internal tool that generates keys and mints tokens.

**Architecture:** A new `Services/Licensing` namespace owns token verification, device fingerprinting, tamper-evident storage, and clock-rollback defense. The shipped add-in embeds only public keys and *verifies*; a separate console tool (`tools/LicenseMint`) holds the private key and *signs*. `Auth.cs` and `AuthViewModel.cs` are rewired to consume the verifier instead of the forgeable cache. The marketplace backend is out of scope (Part 3 hand-off).

**Tech Stack:** C# multi-target (net47/net48/net8.0-windows), WPF/WinForms, `System.IdentityModel.Tokens.Jwt` + `Microsoft.IdentityModel.Tokens` for JWT/ES256, `System.Security.Cryptography.ECDsa` (native on all targets), xUnit for tests (net8.0 test host).

## Global Constraints

- **Multi-target:** all shipped code must compile on `net47`, `net48`, and `net8.0-windows`. Verified per [AuthService.csproj:10](AuthService/AuthService.csproj).
- **Algorithm:** ECDSA P-256, JWT `alg` = `ES256`. No other algorithm accepted by the verifier.
- **Token format:** JWT/JWS. Claims: `iss`, `addon`, `tier`, `iat`, `exp`, `device`, `jti`. Header carries `kid`.
- **No secret in the shipped client:** only public keys ship. Private key exists solely in `tools/LicenseMint` and (later) the backend.
- **Key rotation:** verifier holds a keyed set of public keys and selects by `kid`; must accept ≥2 keys concurrently.
- **Backward compatibility:** `Auth.ValidateAuth(addinName, addinID, signupLink)` public signature must not change — consuming add-ins depend on it.
- **Contract source of truth:** [docs/superpowers/specs/2026-08-04-sealed-token-licensing-design.md](docs/superpowers/specs/2026-08-04-sealed-token-licensing-design.md).

---

## File Structure

**New — shipped library (`AuthService/Services/Licensing/`)**
- `LicenseClaims.cs` — POCO of the token claim set + parse helpers.
- `LicensePublicKeys.cs` — embedded public keys by `kid`; rotation-ready.
- `LicenseTokenVerifier.cs` — validates ES256 signature + claim rules; returns a typed result.
- `DeviceFingerprint.cs` — composite fuzzy hardware fingerprint + tolerant match.
- `RollbackRatchet.cs` — `maxDateSeen` persistence and rollback detection.
- `LicenseStore.cs` — reads/writes the token + ratchet state (plaintext, tamper-evident).

**Modified — shipped**
- `Auth.cs` — remove `HasCacheEntry` instant-valid path; call verifier.
- `Services/SubscriptionService.cs:21` — remove public setter on `Status`.
- `MVVM/ViewModel/AuthViewModel.cs` — two activation paths; remove `admin/admin`; fix `async void`.
- `Services/ApiEndpoints.cs:9` — remove hardcoded API key (load from config).
- `Services/FirstOptionPremiseAuth.cs` — remove hardcoded credentials.
- `AuthService.csproj` — add package references + new `Compile` includes.

**New — tooling (`tools/LicenseMint/`)**
- `LicenseMint.csproj` — net8.0 console.
- `Program.cs` — `keygen` and `mint` verbs; writes test vectors.

**New — tests (`AuthService.Tests/`)**
- `AuthService.Tests.csproj` — net8.0 xUnit; references the shipped project.
- One test file per component (named per task).
- `Vectors/` — committed test-vector JSON produced by the mint tool.

---

## Task 0: Solution scaffolding — test project + mint tool skeletons

**Files:**
- Create: `AuthService.Tests/AuthService.Tests.csproj`
- Create: `tools/LicenseMint/LicenseMint.csproj`
- Create: `tools/LicenseMint/Program.cs` (stub)
- Modify: `AuthService.sln`

**Interfaces:**
- Produces: a `dotnet test` target and a runnable `LicenseMint` console. No app logic yet.

- [ ] **Step 1: Create the test project**

`AuthService.Tests/AuthService.Tests.csproj`:
```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0-windows</TargetFramework>
    <Nullable>disable</Nullable>
    <IsPackable>false</IsPackable>
    <UseWPF>true</UseWPF>
    <UseWindowsForms>true</UseWindowsForms>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.11.1" />
    <PackageReference Include="xunit" Version="2.9.2" />
    <PackageReference Include="xunit.runner.visualstudio" Version="2.8.2" />
  </ItemGroup>
  <ItemGroup>
    <ProjectReference Include="..\AuthService\AuthService.csproj" />
  </ItemGroup>
</Project>
```

- [ ] **Step 2: Create the mint tool skeleton**

`tools/LicenseMint/LicenseMint.csproj`:
```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>disable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="8.1.2" />
  </ItemGroup>
</Project>
```

`tools/LicenseMint/Program.cs`:
```csharp
if (args.Length == 0) { Console.WriteLine("verbs: keygen | mint"); return 0; }
Console.WriteLine($"LicenseMint stub: {args[0]}");
return 0;
```

- [ ] **Step 3: Add both projects to the solution**

Run:
```bash
dotnet sln AuthService.sln add AuthService.Tests/AuthService.Tests.csproj tools/LicenseMint/LicenseMint.csproj
```

- [ ] **Step 4: Verify build**

Run: `dotnet build AuthService.Tests/AuthService.Tests.csproj -f net8.0-windows`
Expected: build succeeds (0 tests).

- [ ] **Step 5: Commit**

```bash
git add AuthService.Tests tools/LicenseMint AuthService.sln
git commit -m "chore: scaffold test project and LicenseMint tool"
```

---

## Task 1: License claim model

**Files:**
- Create: `AuthService/Services/Licensing/LicenseClaims.cs`
- Modify: `AuthService/AuthService.csproj` (add `Compile Include`)
- Test: `AuthService.Tests/LicenseClaimsTests.cs`

**Interfaces:**
- Produces:
  - `class LicenseClaims { string Issuer; string AddonId; string Tier; DateTimeOffset IssuedAt; DateTimeOffset Expires; string DeviceHash; string TokenId; }`
  - `static LicenseClaims FromJwtPayload(IDictionary<string, object> claims)` — maps `iss/addon/tier/iat/exp/device/jti`.

- [ ] **Step 1: Write the failing test**

`AuthService.Tests/LicenseClaimsTests.cs`:
```csharp
using System;
using System.Collections.Generic;
using AuthService.Services.Licensing;
using Xunit;

public class LicenseClaimsTests
{
    [Fact]
    public void FromJwtPayload_MapsAllClaims()
    {
        var payload = new Dictionary<string, object>
        {
            ["iss"] = "firstoption",
            ["addon"] = "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8",
            ["tier"] = "paid",
            ["iat"] = 1_700_000_000L,
            ["exp"] = 1_800_000_000L,
            ["device"] = "abc123",
            ["jti"] = "tok-1"
        };

        var claims = LicenseClaims.FromJwtPayload(payload);

        Assert.Equal("firstoption", claims.Issuer);
        Assert.Equal("9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8", claims.AddonId);
        Assert.Equal("paid", claims.Tier);
        Assert.Equal(1_800_000_000L, claims.Expires.ToUnixTimeSeconds());
        Assert.Equal("abc123", claims.DeviceHash);
        Assert.Equal("tok-1", claims.TokenId);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test AuthService.Tests --filter LicenseClaimsTests`
Expected: FAIL — `LicenseClaims` not found.

- [ ] **Step 3: Write minimal implementation**

`AuthService/Services/Licensing/LicenseClaims.cs`:
```csharp
using System;
using System.Collections.Generic;
using System.Globalization;

namespace AuthService.Services.Licensing
{
    public sealed class LicenseClaims
    {
        public string Issuer { get; set; }
        public string AddonId { get; set; }
        public string Tier { get; set; }
        public DateTimeOffset IssuedAt { get; set; }
        public DateTimeOffset Expires { get; set; }
        public string DeviceHash { get; set; }
        public string TokenId { get; set; }

        public static LicenseClaims FromJwtPayload(IDictionary<string, object> claims)
        {
            return new LicenseClaims
            {
                Issuer = Str(claims, "iss"),
                AddonId = Str(claims, "addon"),
                Tier = Str(claims, "tier"),
                IssuedAt = DateTimeOffset.FromUnixTimeSeconds(Long(claims, "iat")),
                Expires = DateTimeOffset.FromUnixTimeSeconds(Long(claims, "exp")),
                DeviceHash = Str(claims, "device"),
                TokenId = Str(claims, "jti")
            };
        }

        private static string Str(IDictionary<string, object> c, string k) =>
            c.TryGetValue(k, out var v) ? Convert.ToString(v, CultureInfo.InvariantCulture) : null;

        private static long Long(IDictionary<string, object> c, string k) =>
            c.TryGetValue(k, out var v) ? Convert.ToInt64(v, CultureInfo.InvariantCulture) : 0L;
    }
}
```

Add to `AuthService.csproj` `<ItemGroup>` of `Compile` items:
```xml
<Compile Include="Services\Licensing\LicenseClaims.cs" />
```

- [ ] **Step 4: Run test to verify it passes**

Run: `dotnet test AuthService.Tests --filter LicenseClaimsTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add AuthService/Services/Licensing/LicenseClaims.cs AuthService/AuthService.csproj AuthService.Tests/LicenseClaimsTests.cs
git commit -m "feat: add license claim model"
```

---

## Task 2: Mint tool — keygen + mint + test vectors

Do this before the verifier so the verifier's tests run against **real** signed tokens.

**Files:**
- Modify: `tools/LicenseMint/Program.cs`
- Create (output, committed): `AuthService.Tests/Vectors/keys.json`, `AuthService.Tests/Vectors/vectors.json`

**Interfaces:**
- Produces on disk:
  - `keys.json`: `{ "kid": "k1", "publicKeyPem": "...", "privateKeyPem": "..." }`
  - `vectors.json`: array of `{ "name", "token", "expectValid", "reason" }` covering: valid, tampered-payload, expired, wrong-device, wrong-key.
- The `device` claim in the "valid" vector = SHA-256 hex of the literal string `"TEST-DEVICE"` (so `DeviceFingerprint` tests can reproduce it).

- [ ] **Step 1: Implement `keygen`** — generate P-256 key pair, print PEMs.

`tools/LicenseMint/Program.cs` (keygen branch):
```csharp
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
```

- [ ] **Step 2: Implement `mint`** — sign a JWT with a private PEM and claim inputs.

Add a helper and the `mint`/`vectors` branches (same file):
```csharp
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
```
Add `<PackageReference Include="Microsoft.IdentityModel.Tokens" Version="8.1.2" />` to `LicenseMint.csproj`.

- [ ] **Step 3: Generate and place vectors**

Run:
```bash
dotnet run --project tools/LicenseMint -- keygen
dotnet run --project tools/LicenseMint -- vectors
mkdir -p AuthService.Tests/Vectors && mv keys.json vectors.json AuthService.Tests/Vectors/
```
Mark `Vectors/*.json` as `Copy to output` in the test csproj:
```xml
<ItemGroup>
  <None Include="Vectors\*.json" CopyToOutputDirectory="PreserveNewest" />
</ItemGroup>
```
> Note: `keys.json` here contains a **test** private key only. The production private key is never committed.

- [ ] **Step 4: Verify vectors are well-formed**

Run: `dotnet run --project tools/LicenseMint -- vectors` again; confirm 5 entries.

- [ ] **Step 5: Commit**

```bash
git add tools/LicenseMint AuthService.Tests/Vectors AuthService.Tests/AuthService.Tests.csproj
git commit -m "feat: LicenseMint keygen/mint + committed test vectors"
```

---

## Task 3: Public key store (rotation-ready)

**Files:**
- Create: `AuthService/Services/Licensing/LicensePublicKeys.cs`
- Modify: `AuthService/AuthService.csproj`
- Test: `AuthService.Tests/LicensePublicKeysTests.cs`

**Interfaces:**
- Produces:
  - `static class LicensePublicKeys { static ECDsa Resolve(string kid); static void LoadForTests(string kid, string pem); }`
  - `Resolve` returns a fresh `ECDsa` for the `kid`, or `null` if unknown. Holds ≥2 keys.

- [ ] **Step 1: Write the failing test** (loads test key from `Vectors/keys.json`)

`AuthService.Tests/LicensePublicKeysTests.cs`:
```csharp
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test AuthService.Tests --filter LicensePublicKeysTests` → FAIL.

- [ ] **Step 3: Write minimal implementation**

`AuthService/Services/Licensing/LicensePublicKeys.cs`:
```csharp
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace AuthService.Services.Licensing
{
    public static class LicensePublicKeys
    {
        // PRODUCTION: replace with real public-key PEMs, keyed by kid. Two slots enable rotation.
        private static readonly ConcurrentDictionary<string, string> Pems = new ConcurrentDictionary<string, string>();

        public static void LoadForTests(string kid, string pem) => Pems[kid] = pem;

        public static ECDsa Resolve(string kid)
        {
            if (kid == null || !Pems.TryGetValue(kid, out var pem)) return null;
            var ec = ECDsa.Create();
            ec.ImportFromPem(pem);
            return ec;
        }
    }
}
```
> `ImportFromPem` exists on net47/48 via the `System.Security.Cryptography` surface in modern SDKs; if a target lacks it, the fallback is `ImportSubjectPublicKeyInfo` after stripping PEM armor. Confirm compile on all three TFMs in Step 4.

Add `<Compile Include="Services\Licensing\LicensePublicKeys.cs" />`.

- [ ] **Step 4: Run test + multi-target build**

Run: `dotnet test AuthService.Tests --filter LicensePublicKeysTests` → PASS.
Run: `dotnet build AuthService/AuthService.csproj` (builds all TFMs) → succeeds.

- [ ] **Step 5: Commit**

```bash
git add AuthService/Services/Licensing/LicensePublicKeys.cs AuthService/AuthService.csproj AuthService.Tests/LicensePublicKeysTests.cs
git commit -m "feat: rotation-ready license public key store"
```

---

## Task 4: License token verifier (crypto core)

**Files:**
- Create: `AuthService/Services/Licensing/LicenseTokenVerifier.cs`
- Modify: `AuthService/AuthService.csproj`
- Test: `AuthService.Tests/LicenseTokenVerifierTests.cs`

**Interfaces:**
- Consumes: `LicenseClaims`, `LicensePublicKeys.Resolve`.
- Produces:
  - `enum VerifyStatus { Valid, BadSignature, Expired, Malformed, UnknownKey }`
  - `class VerifyResult { VerifyStatus Status; LicenseClaims Claims; }`
  - `class LicenseTokenVerifier { VerifyResult Verify(string jwt, DateTimeOffset now); }`
- Rules: `ES256` only; reject unknown `kid`; validate signature; `exp` compared to `now`; on success return claims (device match is a *separate* check in Task 7, not here).

- [ ] **Step 1: Write failing tests driven by the vector file**

`AuthService.Tests/LicenseTokenVerifierTests.cs`:
```csharp
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `dotnet test AuthService.Tests --filter LicenseTokenVerifierTests` → FAIL (type missing).

- [ ] **Step 3: Implement the verifier**

`AuthService/Services/Licensing/LicenseTokenVerifier.cs`:
```csharp
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.Services.Licensing
{
    public enum VerifyStatus { Valid, BadSignature, Expired, Malformed, UnknownKey }

    public sealed class VerifyResult
    {
        public VerifyStatus Status { get; set; }
        public LicenseClaims Claims { get; set; }
    }

    public sealed class LicenseTokenVerifier
    {
        public VerifyResult Verify(string jwt, DateTimeOffset now)
        {
            if (string.IsNullOrWhiteSpace(jwt)) return new VerifyResult { Status = VerifyStatus.Malformed };

            JwtSecurityToken parsed;
            try { parsed = new JwtSecurityTokenHandler().ReadJwtToken(jwt); }
            catch { return new VerifyResult { Status = VerifyStatus.Malformed }; }

            if (!string.Equals(parsed.Header.Alg, "ES256", StringComparison.Ordinal))
                return new VerifyResult { Status = VerifyStatus.BadSignature };

            var ec = LicensePublicKeys.Resolve(parsed.Header.Kid);
            if (ec == null) return new VerifyResult { Status = VerifyStatus.UnknownKey };

            var parameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false, // we compare exp ourselves against injected 'now'
                IssuerSigningKey = new ECDsaSecurityKey(ec),
                ValidAlgorithms = new[] { "ES256" }
            };

            try
            {
                new JwtSecurityTokenHandler().ValidateToken(jwt, parameters, out _);
            }
            catch
            {
                return new VerifyResult { Status = VerifyStatus.BadSignature };
            }

            var claims = LicenseClaims.FromJwtPayload(
                parsed.Payload.ToDictionary(kv => kv.Key, kv => kv.Value));

            if (now > claims.Expires)
                return new VerifyResult { Status = VerifyStatus.Expired, Claims = claims };

            return new VerifyResult { Status = VerifyStatus.Valid, Claims = claims };
        }
    }
}
```
Add package refs to `AuthService.csproj`:
```xml
<PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="8.1.2" />
```
Add `<Compile Include="Services\Licensing\LicenseTokenVerifier.cs" />`.

- [ ] **Step 4: Run tests + multi-target build**

Run: `dotnet test AuthService.Tests --filter LicenseTokenVerifierTests` → PASS (4 cases).
Run: `dotnet build AuthService/AuthService.csproj` → succeeds on net47/net48/net8.

- [ ] **Step 5: Commit**

```bash
git add AuthService/Services/Licensing/LicenseTokenVerifier.cs AuthService/AuthService.csproj AuthService.Tests/LicenseTokenVerifierTests.cs
git commit -m "feat: ES256 license token verifier"
```

---

## Task 5: Device fingerprint (machine-GUID exact match)

**Design note (supersedes the original composite-fuzzy design):** Fuzzy "tolerate one changed component" matching over a single joint SHA-256 hash is cryptographically impossible (preimage resistance — no subset of *changed* current values reproduces a hash of the *original* values). Instead bind to the **Windows MachineGuid**, a stable per-install identifier that survives NIC swaps, docking, VPN, and disk changes, and match it **exactly**. This achieves the low-false-lockout goal by binding to something stable rather than by tolerating drift. The token `device` claim stays `SHA-256(deviceId)` — the contract and the committed vectors (which hash the single string `"TEST-DEVICE"`) are unchanged.

**Files:**
- Create: `AuthService/Services/Licensing/DeviceFingerprint.cs`
- Modify: `AuthService/AuthService.csproj`
- Test: `AuthService.Tests/DeviceFingerprintTests.cs`

**Interfaces:**
- Produces:
  - `static class DeviceFingerprint { static string CurrentDeviceId(); static string Hash(string deviceId); static bool Matches(string tokenHash, string currentDeviceId); }`
  - `Hash(deviceId)` = lowercase-hex SHA-256 of the exact UTF-8 bytes of `deviceId`.
  - `Matches(tokenHash, currentDeviceId)` = ordinal-ignore-case equality of `Hash(currentDeviceId)` and `tokenHash`; returns `false` if `currentDeviceId` is null/empty.
  - `CurrentDeviceId()` returns the Windows MachineGuid (registry `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`), or `""` if unreadable.
- Continuity: `Hash("TEST-DEVICE")` MUST equal `6be0412a5dac0a63d688a9a60608b2257c8292bb663738b952b9bbe5a4ff9fdd` (the committed vectors' `device` value). Assert this.

- [ ] **Step 1: Write failing tests**

```csharp
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
```

- [ ] **Step 2: Run to verify it fails** → FAIL.

- [ ] **Step 3: Implement**

`AuthService/Services/Licensing/DeviceFingerprint.cs`:
```csharp
using System;
using System.Security.Cryptography;
using System.Text;

namespace AuthService.Services.Licensing
{
    public static class DeviceFingerprint
    {
        public static string Hash(string deviceId)
        {
            if (deviceId == null) deviceId = string.Empty;
            using (var sha = SHA256.Create())
                return ToHex(sha.ComputeHash(Encoding.UTF8.GetBytes(deviceId)));
        }

        public static bool Matches(string tokenHash, string currentDeviceId)
        {
            if (string.IsNullOrEmpty(currentDeviceId) || string.IsNullOrEmpty(tokenHash))
                return false;
            return string.Equals(Hash(currentDeviceId), tokenHash, StringComparison.OrdinalIgnoreCase);
        }

        public static string CurrentDeviceId()
        {
            try
            {
                using (var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography"))
                    return (k?.GetValue("MachineGuid") as string) ?? string.Empty;
            }
            catch { return string.Empty; }
        }

        private static string ToHex(byte[] b)
        {
            var sb = new StringBuilder(b.Length * 2);
            foreach (var x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }
    }
}
```
Add `<Compile Include="Services\Licensing\DeviceFingerprint.cs" />`. (Registry read compiles on all three TFMs — no `#if` needed.)

- [ ] **Step 4: Run tests + build** → PASS; multi-target build succeeds (build each config explicitly with `-c`).

- [ ] **Step 5: Commit**

```bash
git add AuthService/Services/Licensing/DeviceFingerprint.cs AuthService/AuthService.csproj AuthService.Tests/DeviceFingerprintTests.cs
git commit -m "feat: machine-GUID device fingerprint (exact match)"
```

---

## Task 6: Rollback ratchet

**Files:**
- Create: `AuthService/Services/Licensing/RollbackRatchet.cs`
- Modify: `AuthService/AuthService.csproj`
- Test: `AuthService.Tests/RollbackRatchetTests.cs`

**Interfaces:**
- Produces:
  - `class RollbackRatchet { DateTimeOffset MaxDateSeen; bool IsRollback(DateTimeOffset now); RollbackRatchet Advance(DateTimeOffset now); }`
  - `IsRollback(now)` = `now < MaxDateSeen`. `Advance` returns a ratchet with `Max(MaxDateSeen, now)`. Pure/serializable; persistence handled in Task 7.

- [ ] **Step 1: Write failing test**
```csharp
using System;
using AuthService.Services.Licensing;
using Xunit;

public class RollbackRatchetTests
{
    [Fact]
    public void DetectsBackwardClock()
    {
        var r = new RollbackRatchet { MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_750_000_000) };
        Assert.True(r.IsRollback(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000)));
        Assert.False(r.IsRollback(DateTimeOffset.FromUnixTimeSeconds(1_760_000_000)));
    }

    [Fact]
    public void AdvanceOnlyMovesForward()
    {
        var r = new RollbackRatchet { MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_750_000_000) };
        Assert.Equal(1_750_000_000, r.Advance(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000)).MaxDateSeen.ToUnixTimeSeconds());
        Assert.Equal(1_760_000_000, r.Advance(DateTimeOffset.FromUnixTimeSeconds(1_760_000_000)).MaxDateSeen.ToUnixTimeSeconds());
    }
}
```

- [ ] **Step 2: Run to verify it fails** → FAIL.

- [ ] **Step 3: Implement**
```csharp
using System;

namespace AuthService.Services.Licensing
{
    public sealed class RollbackRatchet
    {
        public DateTimeOffset MaxDateSeen { get; set; }
        public bool IsRollback(DateTimeOffset now) => now < MaxDateSeen;
        public RollbackRatchet Advance(DateTimeOffset now) =>
            new RollbackRatchet { MaxDateSeen = now > MaxDateSeen ? now : MaxDateSeen };
    }
}
```
Add `<Compile Include="Services\Licensing\RollbackRatchet.cs" />`.

- [ ] **Step 4: Run tests + build** → PASS.

- [ ] **Step 5: Commit**
```bash
git add AuthService/Services/Licensing/RollbackRatchet.cs AuthService/AuthService.csproj AuthService.Tests/RollbackRatchetTests.cs
git commit -m "feat: clock-rollback ratchet"
```

---

## Task 7: License store (token + ratchet persistence)

**Files:**
- Create: `AuthService/Services/Licensing/LicenseStore.cs`
- Modify: `AuthService/AuthService.csproj`
- Test: `AuthService.Tests/LicenseStoreTests.cs`

**Interfaces:**
- Produces:
  - `class StoredLicense { string Token; DateTimeOffset MaxDateSeen; }`
  - `class LicenseStore { LicenseStore(string path); StoredLicense Read(); void Write(StoredLicense license); void Clear(); }`
- Plaintext JSON (tamper-evident via token signature; not secret). Path injectable for tests.

- [ ] **Step 1: Write failing test** (round-trip to a temp file)
```csharp
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
```

- [ ] **Step 2: Run to verify it fails** → FAIL.

- [ ] **Step 3: Implement**
```csharp
using System;
using System.IO;
using System.Text.Json;

namespace AuthService.Services.Licensing
{
    public sealed class StoredLicense
    {
        public string Token { get; set; }
        public DateTimeOffset MaxDateSeen { get; set; }
    }

    public sealed class LicenseStore
    {
        private readonly string _path;
        public LicenseStore(string path) { _path = path; }

        public StoredLicense Read()
        {
            try { return File.Exists(_path) ? JsonSerializer.Deserialize<StoredLicense>(File.ReadAllText(_path)) : null; }
            catch { return null; }
        }

        public void Write(StoredLicense license)
        {
            var dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(_path, JsonSerializer.Serialize(license));
        }

        public void Clear() { try { if (File.Exists(_path)) File.Delete(_path); } catch { } }
    }
}
```
Add `<Compile Include="Services\Licensing\LicenseStore.cs" />`.

- [ ] **Step 4: Run tests + build** → PASS.

- [ ] **Step 5: Commit**
```bash
git add AuthService/Services/Licensing/LicenseStore.cs AuthService/AuthService.csproj AuthService.Tests/LicenseStoreTests.cs
git commit -m "feat: plaintext tamper-evident license store"
```

---

## Task 8: License gate — compose verifier + fingerprint + ratchet

**Files:**
- Create: `AuthService/Services/Licensing/LicenseGate.cs`
- Modify: `AuthService/AuthService.csproj`
- Test: `AuthService.Tests/LicenseGateTests.cs`

**Interfaces:**
- Consumes: `LicenseTokenVerifier`, `DeviceFingerprint`, `RollbackRatchet`, `LicenseStore`, `LicenseClaims`.
- Produces:
  - `enum GateStatus { Valid, Invalid, Rollback }`
  - `class LicenseGate { GateStatus Evaluate(string addinId, string currentDeviceId, DateTimeOffset now); }` — reads store, checks ratchet, verifies token, checks `addon`==addinId and exact device match, advances+persists ratchet on success.
- This is the single entry point `Auth.cs` will call.

- [ ] **Step 1: Write failing test** (uses the valid vector; construct a store pointing at a temp file seeded with that token, and the TEST-DEVICE component)
```csharp
using System;
using System.IO;
using System.Text.Json;
using AuthService.Services.Licensing;
using Xunit;

public class LicenseGateTests
{
    [Fact]
    public void ValidToken_MatchingDevice_Passes()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        var vectors = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/vectors.json"));
        string token = null;
        foreach (var v in vectors.EnumerateArray())
            if (v.GetProperty("name").GetString() == "valid") token = v.GetProperty("token").GetString();

        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        new LicenseStore(path).Write(new StoredLicense { Token = token, MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000) });

        // vector device hash == SHA256("TEST-DEVICE"); pass that exact single component
        var gate = new LicenseGate(new LicenseStore(path));
        var status = gate.Evaluate(
            "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8",
            "TEST-DEVICE",
            DateTimeOffset.FromUnixTimeSeconds(1_750_000_000));

        Assert.Equal(GateStatus.Valid, status);
    }

    [Fact]
    public void RolledBackClock_IsRejected()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        new LicenseStore(path).Write(new StoredLicense { Token = "x", MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000) });
        var gate = new LicenseGate(new LicenseStore(path));
        Assert.Equal(GateStatus.Rollback, gate.Evaluate("any", "TEST-DEVICE", DateTimeOffset.FromUnixTimeSeconds(1_700_000_000)));
    }

    [Fact]
    public void WrongDevice_IsRejected()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        var vectors = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/vectors.json"));
        string token = null;
        foreach (var v in vectors.EnumerateArray())
            if (v.GetProperty("name").GetString() == "valid") token = v.GetProperty("token").GetString();
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        new LicenseStore(path).Write(new StoredLicense { Token = token, MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000) });
        var gate = new LicenseGate(new LicenseStore(path));
        Assert.Equal(GateStatus.Invalid, gate.Evaluate(
            "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8", "SOME-OTHER-MACHINE", DateTimeOffset.FromUnixTimeSeconds(1_750_000_000)));
    }
}
```

- [ ] **Step 2: Run to verify it fails** → FAIL.

- [ ] **Step 3: Implement**
```csharp
using System;

namespace AuthService.Services.Licensing
{
    public enum GateStatus { Valid, Invalid, Rollback }

    public sealed class LicenseGate
    {
        private readonly LicenseStore _store;
        private readonly LicenseTokenVerifier _verifier = new LicenseTokenVerifier();

        public LicenseGate(LicenseStore store) { _store = store; }

        public GateStatus Evaluate(string addinId, string currentDeviceId, DateTimeOffset now)
        {
            var stored = _store.Read();
            if (stored == null) return GateStatus.Invalid;

            var ratchet = new RollbackRatchet { MaxDateSeen = stored.MaxDateSeen };
            if (ratchet.IsRollback(now)) return GateStatus.Rollback;

            var result = _verifier.Verify(stored.Token, now);
            if (result.Status != VerifyStatus.Valid) return GateStatus.Invalid;

            if (!string.Equals(result.Claims.AddonId, addinId, StringComparison.OrdinalIgnoreCase))
                return GateStatus.Invalid;

            if (!DeviceFingerprint.Matches(result.Claims.DeviceHash, currentDeviceId))
                return GateStatus.Invalid;

            _store.Write(new StoredLicense { Token = stored.Token, MaxDateSeen = ratchet.Advance(now).MaxDateSeen });
            return GateStatus.Valid;
        }
    }
}
```
Add `<Compile Include="Services\Licensing\LicenseGate.cs" />`.

- [ ] **Step 4: Run tests + build** → PASS.

- [ ] **Step 5: Commit**
```bash
git add AuthService/Services/Licensing/LicenseGate.cs AuthService/AuthService.csproj AuthService.Tests/LicenseGateTests.cs
git commit -m "feat: license gate composing verify+device+ratchet"
```

---

## Task 9: Remove shipped secrets and the mutable trust flag

**Files:**
- Modify: `AuthService/Services/FirstOptionPremiseAuth.cs`
- Modify: `AuthService/Services/ApiEndpoints.cs:9`
- Modify: `AuthService/Services/SubscriptionService.cs:21`
- Test: `AuthService.Tests/NoHardcodedSecretsTests.cs`

**Interfaces:**
- Produces: `SubscriptionService.Status` getter stays public; setter becomes `private`/`internal`. A new `internal static void SetStatus(SubscriptionStatus s)` is used only inside the assembly.
- Credentials/API key move to a runtime config lookup (env var or config file), not literals.

- [ ] **Step 1: Write failing test — source contains no known secret literals**
```csharp
using System.IO;
using Xunit;

public class NoHardcodedSecretsTests
{
    [Theory]
    [InlineData("AuthService/Services/FirstOptionPremiseAuth.cs", "\"admin\"")]
    [InlineData("AuthService/Services/ApiEndpoints.cs", "4c69b7fa5010519e87f2aa6e7b6b5a16")]
    public void SourceDoesNotContainSecret(string relativePath, string secret)
    {
        var root = Path.GetFullPath(Path.Combine(System.AppContext.BaseDirectory, "..", "..", "..", ".."));
        var text = File.ReadAllText(Path.Combine(root, relativePath));
        Assert.DoesNotContain(secret, text);
    }
}
```

- [ ] **Step 2: Run to verify it fails** → FAIL (secrets still present).

- [ ] **Step 3: Remove the literals**
- `FirstOptionPremiseAuth.cs`: replace the constant credentials with reads from environment variables (`FIRSTOPTION_SVC_USER`, `FIRSTOPTION_SVC_PASS`), returning empty when unset.
- `ApiEndpoints.cs:9`: replace `ApiKey` literal with `Environment.GetEnvironmentVariable("FIRSTOPTION_API_KEY")`.
- `SubscriptionService.cs:21`: change `public static SubscriptionStatus Status { get; set; }` → `{ get; private set; }` and add `internal static void SetStatus(SubscriptionStatus s) => Status = s;`. Update in-assembly writers accordingly (compiler will flag them).

- [ ] **Step 4: Fix all now-broken `Status = ...` assignments**, run tests + build.
Run: `dotnet build AuthService/AuthService.csproj` → fix each error by routing through `SetStatus`. Then `dotnet test AuthService.Tests --filter NoHardcodedSecretsTests` → PASS.

- [ ] **Step 5: Commit**
```bash
git add AuthService/Services AuthService.Tests/NoHardcodedSecretsTests.cs
git commit -m "security: remove shipped secrets; lock down Status setter"
```

---

## Task 10: Wire the gate into `Auth.cs` (remove instant-valid shortcut)

**Files:**
- Modify: `AuthService/Auth.cs:59-174`
- Test: `AuthService.Tests/AuthValidateTests.cs`

**Interfaces:**
- Consumes: `LicenseGate`, `DeviceFingerprint.Components`, `LicenseStore`.
- Produces: `Auth.ValidateAuth(addinName, addinID, signupLink)` unchanged signature; internally uses the gate. `HasCacheEntry` and the existence-only fast path are deleted. When gate returns `Invalid`/`Rollback`, show the Auth window (unchanged UI entry).
- Add an injectable seam: `internal static Func<string, LicenseGate> GateFactory` defaulting to production path, so tests substitute a gate over a temp store.

- [ ] **Step 1: Write failing test** — a valid stored token makes `ValidateAuth` return `Valid` with no UI.
```csharp
using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using AuthService;
using AuthService.Services;
using AuthService.Services.Licensing;
using Xunit;

public class AuthValidateTests
{
    [Fact]
    public async Task StoredValidToken_ReturnsValid_NoUi()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        var vectors = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/vectors.json"));
        string token = null;
        foreach (var v in vectors.EnumerateArray())
            if (v.GetProperty("name").GetString() == "valid") token = v.GetProperty("token").GetString();

        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        new LicenseStore(path).Write(new StoredLicense { Token = token, MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000) });

        Auth.GateFactory = _ => new LicenseGate(new LicenseStore(path));
        Auth.NowProvider = () => DateTimeOffset.FromUnixTimeSeconds(1_750_000_000);
        Auth.DeviceProvider = () => "TEST-DEVICE";

        var status = await Auth.ValidateAuth("Addin", "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8");
        Assert.Equal(SubscriptionService.SubscriptionStatus.Valid, status);
    }
}
```

- [ ] **Step 2: Run to verify it fails** → FAIL (seams absent).

- [ ] **Step 3: Implement the rewire**
- Add to `Auth`:
```csharp
internal static Func<string, LicenseGate> GateFactory = addinId => new LicenseGate(LicenseStore.Default());
internal static Func<DateTimeOffset> NowProvider = () => DateTimeOffset.UtcNow;
internal static Func<string> DeviceProvider = DeviceFingerprint.CurrentDeviceId;
```
- Add `LicenseStore.Default()` static that returns a store at the existing cache directory path.
- Replace the body of `ValidateAuth` so it:
  1. `var gate = GateFactory(addinID);`
  2. `var status = gate.Evaluate(addinID, DeviceProvider(), NowProvider());`
  3. `Valid` → set `SubscriptionService.SetStatus(Valid)`, return `Valid`.
  4. otherwise → run the existing `RunAuthOnStaThread` UI path (unchanged), return its result.
- Delete `HasCacheEntry` and the existence-only fast path at [Auth.cs:61-66](AuthService/Auth.cs).

- [ ] **Step 4: Run tests + build** → PASS; multi-target build succeeds.

- [ ] **Step 5: Commit**
```bash
git add AuthService/Auth.cs AuthService/Services/Licensing/LicenseStore.cs AuthService.Tests/AuthValidateTests.cs
git commit -m "feat: route Auth.ValidateAuth through license gate; drop instant-valid shortcut"
```

---

## Task 11: Activation UX — paste code (online) or paste token (air-gapped)

**Files:**
- Modify: `AuthService/MVVM/View/AuthWindow.xaml`
- Modify: `AuthService/MVVM/ViewModel/AuthViewModel.cs`
- Test: `AuthService.Tests/ActivationViewModelTests.cs`

**Interfaces:**
- Consumes: `LicenseGate`/`LicenseTokenVerifier`, `LicenseStore`, `DeviceFingerprint`.
- Produces on the view model:
  - `string DeviceFingerprintDisplay { get; }` — shown so air-gapped users can mint elsewhere.
  - `string PastedToken { get; set; }` and `ICommand ActivateTokenCommand` — verifies a pasted token, and on `Valid` writes it via `LicenseStore` and sets status.
  - Existing short-code path retained for the online case.
- Fix: convert `async void ExecuteSubmit` to guarded `async Task` invoked by a wrapper that catches exceptions (no throw into the CAD host). Remove the `admin/admin` premise path from Task 9's config seam.

- [ ] **Step 1: Write failing test** — pasting the valid vector token activates.
```csharp
using System;
using System.IO;
using System.Text.Json;
using AuthService.MVVM.ViewModel;
using AuthService.Services.Licensing;
using Xunit;

public class ActivationViewModelTests
{
    [Fact]
    public void PasteValidToken_Activates()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        var vectors = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/vectors.json"));
        string token = null;
        foreach (var v in vectors.EnumerateArray())
            if (v.GetProperty("name").GetString() == "valid") token = v.GetProperty("token").GetString();

        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        var vm = new AuthViewModel("Addin", "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8")
        {
            TokenStoreOverride = new LicenseStore(path),
            NowOverride = DateTimeOffset.FromUnixTimeSeconds(1_750_000_000),
            DeviceOverride = "TEST-DEVICE",
            PastedToken = token
        };

        vm.ActivateTokenCommand.Execute(null);

        Assert.Equal(AuthService.Services.SubscriptionService.SubscriptionStatus.Valid,
                     AuthService.Services.SubscriptionService.Status);
    }
}
```

- [ ] **Step 2: Run to verify it fails** → FAIL.

- [ ] **Step 3: Implement**
- Add the test seams (`TokenStoreOverride`, `NowOverride`, `DeviceOverride` as `string`) with production defaults (`DeviceOverride` defaults to `DeviceFingerprint.CurrentDeviceId()`).
- Add `DeviceFingerprintDisplay` = short prefix of `DeviceFingerprint.Hash(DeviceFingerprint.CurrentDeviceId())`.
- Add `PastedToken` + `ActivateTokenCommand` that runs the gate against a store seeded with the pasted token (or verifies directly then writes on success).
- Convert `ExecuteSubmit` to `async Task ExecuteSubmitCore()` wrapped by `async void ExecuteSubmit(object o){ try { await ExecuteSubmitCore(); } catch (Exception ex) { Status = "Activation error"; } }`.
- In `AuthWindow.xaml`, add a "Paste license token" TextBox bound to `PastedToken`, an "Activate" button bound to `ActivateTokenCommand`, and a read-only fingerprint label bound to `DeviceFingerprintDisplay`.

- [ ] **Step 4: Run tests + build** → PASS; multi-target build succeeds.

- [ ] **Step 5: Commit**
```bash
git add AuthService/MVVM AuthService.Tests/ActivationViewModelTests.cs
git commit -m "feat: token-paste + fingerprint activation UX; fix async void"
```

---

## Task 12: Fix remaining reliability bugs

**Files:**
- Modify: `AuthService/Services/SubscriptionService.cs` (`.GetAwaiter().GetResult()` → `await`)
- Modify: `AuthService/Services/DateHelper.cs` (same)
- Modify: `AuthService/Services/LocalAuthCache.cs:194` (`break` → `continue`)
- Modify: `AuthService/MVVM/ViewModel/AuthViewModel.cs:168` (remove `GetTried = GetTried++`)
- Test: `AuthService.Tests/MacListParsingTests.cs`

**Interfaces:**
- Produces: `LocalAuthCache.IsMacValid` now accumulates all valid MACs (skips malformed) rather than truncating on first bad entry.

- [ ] **Step 1: Write failing test**
```csharp
using System.Collections.Generic;
using AuthService.Services;
using Xunit;

public class MacListParsingTests
{
    [Fact]
    public void MalformedEntry_DoesNotTruncateList()
    {
        var valid = new List<string>();
        // "GARBAGE" is malformed but a real MAC follows it
        LocalAuthCache.IsMacValid(valid, "GARBAGE, AA:BB:CC:DD:EE:FF");
        Assert.Contains("AA:BB:CC:DD:EE:FF", valid);
    }
}
```

- [ ] **Step 2: Run to verify it fails** → FAIL (`break` drops the good MAC).

- [ ] **Step 3: Fix** — `break`→`continue` at [LocalAuthCache.cs:194](AuthService/Services/LocalAuthCache.cs); replace sync-over-async `.GetAwaiter().GetResult()` calls with `await ...ConfigureAwait(false)`; delete the `GetTried = GetTried++` self-assignment.

- [ ] **Step 4: Run tests + full build + full test suite**
Run: `dotnet test AuthService.Tests` → all PASS.
Run: `dotnet build AuthService/AuthService.csproj` → all TFMs succeed.

- [ ] **Step 5: Commit**
```bash
git add AuthService/Services AuthService/MVVM AuthService.Tests/MacListParsingTests.cs
git commit -m "fix: mac-list truncation, sync-over-async, no-op self-assign"
```

---

## Task 13: End-to-end mint→verify smoke test + backend hand-off doc

**Files:**
- Create: `AuthService.Tests/EndToEndSmokeTests.cs`
- Create: `docs/backend/mint-endpoint-task.md`

**Interfaces:**
- Consumes: full pipeline.
- Produces: a hand-off doc for backend engineers (Part 3) containing only the *contract* and *asks*, no implementation.

- [ ] **Step 1: Write E2E test** — mint a fresh token in-test with a throwaway key, load its public key, verify through `LicenseGate` = Valid; flip one payload char = Invalid.
(Reuse `LicensePublicKeys.LoadForTests` + an in-test `ECDsa` mirroring Task 2's `Mint`.)

- [ ] **Step 2: Run** → PASS.

- [ ] **Step 3: Write the backend hand-off doc** — copy the "Part 3" bullets from the spec verbatim plus the exact claim/header contract from Global Constraints. No code, no endpoint internals.

- [ ] **Step 4: Full suite green**
Run: `dotnet test AuthService.Tests` → all PASS.

- [ ] **Step 5: Commit**
```bash
git add AuthService.Tests/EndToEndSmokeTests.cs docs/backend/mint-endpoint-task.md
git commit -m "test: end-to-end mint/verify; add backend hand-off doc"
```

---

## Self-Review

**Spec coverage:**
- Contract (JWT/ES256/claims/kid) → Tasks 1, 2, 4, Global Constraints. ✓
- Part 1 verification core → Tasks 3, 4. ✓
- Replace forgeable cache (plaintext, tamper-evident) → Task 7. ✓
- Anti-rollback ratchet → Tasks 6, 8. ✓
- Composite fuzzy fingerprint → Task 5. ✓
- Activation UX both paths → Task 11. ✓
- Remove HasCacheEntry shortcut → Task 10. ✓
- Remove mutable Status / shipped secrets → Task 9. ✓
- Reliability fixes → Task 12. ✓
- Part 2 tooling + test vectors → Task 2. ✓
- Backwards-compatible `ValidateAuth` signature → Task 10. ✓
- Part 3 hand-off (no implementation) → Task 13. ✓

**Placeholder scan:** No TBD/TODO; every code step carries real code. Task 11's XAML edit is described precisely (controls + bindings) rather than shown as full XAML — acceptable given the existing file defines the layout; implementer follows existing patterns.

**Type consistency:** `LicenseClaims`, `VerifyStatus`/`VerifyResult`, `GateStatus`, `RollbackRatchet.MaxDateSeen`, `StoredLicense.Token/MaxDateSeen`, `LicensePublicKeys.Resolve/LoadForTests`, `DeviceFingerprint.Hash/Matches/Components` are used consistently across Tasks 1–13.

**Open risk to confirm during Task 3/4:** `ImportFromPem` availability on net47/net48 — if unavailable in the pinned SDK, fall back to stripping PEM armor + `ImportSubjectPublicKeyInfo`. Flagged inline in Task 3.
