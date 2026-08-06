using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Config from environment:
//   FIRSTOPTION_PRIVATE_PEM_PATH  path to the ES256 private key PEM (never ships to clients)
//   FIRSTOPTION_KID               key id embedded in the token header (e.g. "k1")
//   FIRSTOPTION_ADDON             addon GUID the tokens license
//   FIRSTOPTION_MARKETPLACE_URL   redemptions endpoint base, e.g. https://marketplace.firstoption-es.com/api/subscriptions/redemptions
string privPem = File.ReadAllText(Environment.GetEnvironmentVariable("FIRSTOPTION_PRIVATE_PEM_PATH"));
string kid     = Environment.GetEnvironmentVariable("FIRSTOPTION_KID") ?? "k1";
string addon   = Environment.GetEnvironmentVariable("FIRSTOPTION_ADDON");
string marketUrl = Environment.GetEnvironmentVariable("FIRSTOPTION_MARKETPLACE_URL");
var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };

app.MapPost("/activate", async (HttpRequest req) =>
{
    using var doc = await JsonDocument.ParseAsync(req.Body);
    string code   = doc.RootElement.GetProperty("code").GetString();
    string device = doc.RootElement.GetProperty("device").GetString();
    if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(device))
        return Results.BadRequest(new { error = "code and device are required" });

    // Validate the code against the marketplace (unauthenticated redemptions endpoint).
    var (ok, endDateUnix) = await ValidateCodeAsync(http, marketUrl, code);
    if (!ok) return Results.BadRequest(new { error = "invalid or inactive code" });

    long iat = DateTimeOffset.UtcNow.AddMinutes(-5).ToUnixTimeSeconds();
    long exp = endDateUnix;
    string token = Mint(privPem, kid, addon, "paid", iat, exp, device);
    return Results.Ok(new { token });
});

app.Run();

static async Task<(bool ok, long endDateUnix)> ValidateCodeAsync(HttpClient http, string baseUrl, string code)
{
    try
    {
        var url = baseUrl + "?code=" + Uri.EscapeDataString(code);
        using var resp = await http.GetAsync(url);
        if (!resp.IsSuccessStatusCode) return (false, 0);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var root = doc.RootElement;
        if (!root.TryGetProperty("success", out var s) || !s.GetBoolean()) return (false, 0);
        var sub = root.GetProperty("payload").GetProperty("subscription");
        if (!string.Equals(sub.GetProperty("status").GetString(), "active", StringComparison.OrdinalIgnoreCase))
            return (false, 0);
        var end = sub.GetProperty("end_date").GetDateTime();
        return (true, new DateTimeOffset(end, TimeSpan.Zero).ToUnixTimeSeconds());
    }
    catch { return (false, 0); }
}

static string Mint(string privPem, string kid, string addon, string tier, long iat, long exp, string device)
{
    using var ec = ECDsa.Create();
    ec.ImportFromPem(privPem);
    var key = new ECDsaSecurityKey(ec) { KeyId = kid };
    key.CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false };
    var creds = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256);
    var token = new JwtSecurityToken(claims: new[]
    {
        new Claim("iss", "firstoption"),
        new Claim("addon", addon),
        new Claim("tier", tier),
        new Claim("iat", iat.ToString()),
        new Claim("exp", exp.ToString()),
        new Claim("device", device),
        new Claim("jti", Guid.NewGuid().ToString()),
    }, signingCredentials: creds);
    return new JwtSecurityTokenHandler().WriteToken(token);
}
