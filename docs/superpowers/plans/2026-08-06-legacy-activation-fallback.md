# Legacy Activation Fallback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an interim "legacy" activation path: when a customer enters a purchase code and the real mint service is not yet deployed, validate the code against the marketplace the old way, register the machine's device hash into the marketplace database — but grant NO access. The provider reads those device hashes from the DB and mints tokens manually until MintService is live.

**Architecture:** A new `LegacyActivationClient` does a GET to the marketplace redemptions endpoint (validate the code) then a POST to the redeem endpoint carrying the device hash (register it). The `AuthViewModel` code branch routes to this legacy client instead of the mint client whenever the mint URL is not configured. The legacy path is deliberately terminal — it shows a "your license will be issued shortly" message and never calls `SetStatus(Valid)` or writes a token, preserving the no-bypass invariant.

**Tech Stack:** C# multi-target (net47/net48/net8.0-windows), `System.Net.Http`, `System.Text.Json`, xUnit with a stub `HttpMessageHandler` (no real network).

## Global Constraints

- **No access granted:** the legacy path MUST NEVER call `SubscriptionService.SetStatus(Valid)` nor write to `LicenseStore`. It only registers a device and shows an informational message. Verified by test.
- **Device value parity:** the value sent to the redeem endpoint MUST be `DeviceFingerprint.Hash(DeviceOverride)` (= hex SHA-256 of the MachineGuid) — the exact value a manually-minted token's `device` claim must carry. NOT a raw MAC list.
- **Old endpoint shapes (verbatim):**
  - GET `https://marketplace.firstoption-es.com/api/subscriptions/redemptions?code={code}`
  - POST `https://marketplace.firstoption-es.com/api/subscriptions/redeem?code={code}&data[]={value}`
- **Routing:** the code branch uses the legacy path when the mint endpoint is not configured (mint URL unset or still the `REPLACE-ME.invalid` placeholder), and the real mint path once a mint URL is set. No manual flag flip required.
- **Multi-target:** all shipped code compiles on net47, net48, net8.0-windows. Build each config explicitly with `-c "<name>"` (a bare `dotnet build` only builds the default config).
- **Shipped code adds new files to the explicit `<Compile>` list** in `AuthService/AuthService.csproj` (project has `EnableDefaultCompileItems=false`).

---

## File Structure

**New — shipped**
- `AuthService/Services/Licensing/LegacyActivationClient.cs` — `ILegacyActivationClient` + `LegacyActivationResult` + `HttpLegacyActivationClient` (GET-validate then POST-register).

**Modified — shipped**
- `AuthService/Services/Licensing/MintClient.cs` — extend `ActivationEndpoints` with `MarketplaceRedemptionsUrl`, `MarketplaceRedeemUrl`, and `MintConfigured`.
- `AuthService/MVVM/ViewModel/AuthViewModel.cs` — add `LegacyClientOverride` + `UseLegacyActivation` seams; route the code branch; add `RegisterLegacyAsync`.
- `AuthService/AuthService.csproj` — add the new `Compile` include.

**New — tests**
- `AuthService.Tests/LegacyActivationClientTests.cs`
- (extend) `AuthService.Tests/ActivationRoutingTests.cs`

---

## Task 1: LegacyActivationClient

**Files:**
- Create: `AuthService/Services/Licensing/LegacyActivationClient.cs`
- Modify: `AuthService/Services/Licensing/MintClient.cs` (extend `ActivationEndpoints`)
- Modify: `AuthService/AuthService.csproj`
- Test: `AuthService.Tests/LegacyActivationClientTests.cs`

**Interfaces:**
- Consumes: `System.Net.Http.HttpClient`.
- Produces:
  - `class LegacyActivationResult { bool CodeValid; bool Registered; string Error; }`
  - `interface ILegacyActivationClient { Task<LegacyActivationResult> RegisterAsync(string code, string deviceHash); }`
  - `class HttpLegacyActivationClient : ILegacyActivationClient { HttpLegacyActivationClient(HttpClient http, string redemptionsUrl, string redeemUrl); }`
  - `ActivationEndpoints.MarketplaceRedemptionsUrl` / `.MarketplaceRedeemUrl` (string) / `.MintConfigured` (bool).
- Semantics of `RegisterAsync`:
  - GET `{redemptionsUrl}?code={code}` — if non-2xx or JSON `success != true` → `{CodeValid=false, Registered=false, Error="Code not found or server unavailable"}`.
  - else POST `{redeemUrl}?code={code}&data[]={deviceHash}` — if non-2xx → `{CodeValid=true, Registered=false, Error="Could not register this device"}`; else `{CodeValid=true, Registered=true}`.
  - any exception → `{CodeValid=false, Registered=false, Error="Could not reach the activation server"}`.

- [ ] **Step 1: Write the failing test**

`AuthService.Tests/LegacyActivationClientTests.cs`:
```csharp
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AuthService.Services.Licensing;
using Xunit;

public class LegacyActivationClientTests
{
    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Queue<HttpResponseMessage> _responses;
        public readonly List<string> RequestUrls = new List<string>();
        public StubHandler(params HttpResponseMessage[] responses) => _responses = new Queue<HttpResponseMessage>(responses);
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            RequestUrls.Add(request.RequestUri.ToString());
            return Task.FromResult(_responses.Dequeue());
        }
    }

    private static HttpResponseMessage Json(HttpStatusCode code, string body) =>
        new HttpResponseMessage(code) { Content = new StringContent(body) };

    [Fact]
    public async Task ValidCode_RegistersDeviceHash()
    {
        var stub = new StubHandler(
            Json(HttpStatusCode.OK, "{\"success\":true,\"payload\":{}}"), // GET redemptions
            Json(HttpStatusCode.OK, "{\"success\":true}"));                 // POST redeem
        var client = new HttpLegacyActivationClient(new HttpClient(stub),
            "https://mkt.test/redemptions", "https://mkt.test/redeem");

        var result = await client.RegisterAsync("aWiS1Tbo2bm", "6be0412a-devicehash");

        Assert.True(result.CodeValid);
        Assert.True(result.Registered);
        Assert.Contains("code=aWiS1Tbo2bm", stub.RequestUrls[0]);
        Assert.Contains("redeem", stub.RequestUrls[1]);
        Assert.Contains("data%5B%5D=6be0412a-devicehash", stub.RequestUrls[1]); // data[] url-encoded
    }

    [Fact]
    public async Task UnknownCode_DoesNotRegister()
    {
        var stub = new StubHandler(Json(HttpStatusCode.OK, "{\"success\":false}")); // GET says not found
        var client = new HttpLegacyActivationClient(new HttpClient(stub),
            "https://mkt.test/redemptions", "https://mkt.test/redeem");

        var result = await client.RegisterAsync("nope", "devhash");

        Assert.False(result.CodeValid);
        Assert.False(result.Registered);
        Assert.Single(stub.RequestUrls); // never POSTed
    }

    [Fact]
    public async Task RedeemFails_ReportsNotRegistered()
    {
        var stub = new StubHandler(
            Json(HttpStatusCode.OK, "{\"success\":true}"),
            Json(HttpStatusCode.InternalServerError, ""));
        var client = new HttpLegacyActivationClient(new HttpClient(stub),
            "https://mkt.test/redemptions", "https://mkt.test/redeem");

        var result = await client.RegisterAsync("code", "devhash");

        Assert.True(result.CodeValid);
        Assert.False(result.Registered);
        Assert.False(string.IsNullOrEmpty(result.Error));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `dotnet test AuthService.Tests --filter LegacyActivationClientTests`
Expected: FAIL — `HttpLegacyActivationClient` not found.

- [ ] **Step 3: Implement**

`AuthService/Services/Licensing/LegacyActivationClient.cs`:
```csharp
using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace AuthService.Services.Licensing
{
    public sealed class LegacyActivationResult
    {
        public bool CodeValid { get; set; }
        public bool Registered { get; set; }
        public string Error { get; set; }
    }

    public interface ILegacyActivationClient
    {
        Task<LegacyActivationResult> RegisterAsync(string code, string deviceHash);
    }

    // Interim fallback used until the real mint service is deployed. Validates the code
    // against the marketplace the old way (GET redemptions), then registers the device
    // hash (POST redeem, data[]=hash). It NEVER grants access - the provider reads the
    // registered hashes from the marketplace DB and mints tokens manually.
    public sealed class HttpLegacyActivationClient : ILegacyActivationClient
    {
        private readonly HttpClient _http;
        private readonly string _redemptionsUrl;
        private readonly string _redeemUrl;

        public HttpLegacyActivationClient(HttpClient http, string redemptionsUrl, string redeemUrl)
        {
            _http = http;
            _redemptionsUrl = redemptionsUrl;
            _redeemUrl = redeemUrl;
        }

        public async Task<LegacyActivationResult> RegisterAsync(string code, string deviceHash)
        {
            try
            {
                var getUrl = _redemptionsUrl + "?code=" + Uri.EscapeDataString(code);
                using (var getResp = await _http.GetAsync(getUrl).ConfigureAwait(false))
                {
                    if (!getResp.IsSuccessStatusCode)
                        return new LegacyActivationResult { CodeValid = false, Error = "Code not found or server unavailable" };

                    var getBody = getResp.Content == null ? string.Empty : await getResp.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (!JsonSuccess(getBody))
                        return new LegacyActivationResult { CodeValid = false, Error = "Code not found" };
                }

                var postUrl = _redeemUrl + "?code=" + Uri.EscapeDataString(code) + "&data[]=" + Uri.EscapeDataString(deviceHash);
                using (var postResp = await _http.PostAsync(postUrl, null).ConfigureAwait(false))
                {
                    if (!postResp.IsSuccessStatusCode)
                        return new LegacyActivationResult { CodeValid = true, Registered = false, Error = "Could not register this device" };
                    return new LegacyActivationResult { CodeValid = true, Registered = true };
                }
            }
            catch (Exception)
            {
                return new LegacyActivationResult { CodeValid = false, Registered = false, Error = "Could not reach the activation server" };
            }
        }

        private static bool JsonSuccess(string body)
        {
            try
            {
                using (var doc = JsonDocument.Parse(body))
                    return doc.RootElement.TryGetProperty("success", out var s)
                        && s.ValueKind == JsonValueKind.True;
            }
            catch { return false; }
        }
    }
}
```

Extend `ActivationEndpoints` in `AuthService/Services/Licensing/MintClient.cs` (add these members to the existing static class):
```csharp
        public static string MarketplaceRedemptionsUrl =>
            Environment.GetEnvironmentVariable("FIRSTOPTION_MARKETPLACE_URL")
            ?? "https://marketplace.firstoption-es.com/api/subscriptions/redemptions";

        public static string MarketplaceRedeemUrl =>
            Environment.GetEnvironmentVariable("FIRSTOPTION_MARKETPLACE_REDEEM_URL")
            ?? "https://marketplace.firstoption-es.com/api/subscriptions/redeem";

        // The real mint service is "configured" once FIRSTOPTION_MINT_URL is set to a
        // real URL (not unset, not the placeholder). Until then the client uses the
        // legacy registration fallback.
        public static bool MintConfigured
        {
            get
            {
                var url = Environment.GetEnvironmentVariable("FIRSTOPTION_MINT_URL");
                return !string.IsNullOrWhiteSpace(url) && url.IndexOf("REPLACE-ME.invalid", StringComparison.OrdinalIgnoreCase) < 0;
            }
        }
```

Add to `AuthService.csproj` `<Compile>` list:
```xml
<Compile Include="Services\Licensing\LegacyActivationClient.cs" />
```

- [ ] **Step 4: Run tests + multi-target build**

Run: `dotnet test AuthService.Tests --filter LegacyActivationClientTests` → PASS (3 cases).
Run each config: `dotnet build AuthService/AuthService.csproj -c "Net Framework 4.7"`, `-c "Net Framework 4.8.1"`, `-c "Net8.0-windows"` → all succeed.

- [ ] **Step 5: Commit**

```bash
git add AuthService/Services/Licensing/LegacyActivationClient.cs AuthService/Services/Licensing/MintClient.cs AuthService/AuthService.csproj AuthService.Tests/LegacyActivationClientTests.cs
git commit -m "feat: legacy activation client (validate code, register device hash, no access)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Route the code branch through the legacy fallback

**Files:**
- Modify: `AuthService/MVVM/ViewModel/AuthViewModel.cs`
- Test: `AuthService.Tests/ActivationRoutingTests.cs`

**Interfaces:**
- Consumes: `ILegacyActivationClient`, `LegacyActivationResult`, `ActivationEndpoints.MintConfigured`, `DeviceFingerprint.Hash`.
- Produces on the view model:
  - `ILegacyActivationClient LegacyClientOverride { get; set; }` (test seam; production default is an `HttpLegacyActivationClient` over a shared `HttpClient` + `ActivationEndpoints` URLs).
  - `bool UseLegacyActivation { get; set; }` (production default `!ActivationEndpoints.MintConfigured`).
  - `RegisterLegacyAsync(string code)` — private; called by the code branch when `UseLegacyActivation` is true.
- Behavior: on `Registered` → shows an informational message including the device hash and does NOT grant access; on failure → shows an error. Never `SetStatus(Valid)`, never writes `LicenseStore`.

- [ ] **Step 1: Write the failing tests** (append to `ActivationRoutingTests.cs`)

Add a fake and three tests inside the existing `ActivationRoutingTests` class:
```csharp
    private sealed class FakeLegacyClient : AuthService.Services.Licensing.ILegacyActivationClient
    {
        private readonly AuthService.Services.Licensing.LegacyActivationResult _r;
        public string LastCode; public string LastDevice;
        public FakeLegacyClient(AuthService.Services.Licensing.LegacyActivationResult r) { _r = r; }
        public Task<AuthService.Services.Licensing.LegacyActivationResult> RegisterAsync(string code, string deviceHash)
        { LastCode = code; LastDevice = deviceHash; return Task.FromResult(_r); }
    }

    [Fact]
    public async Task Legacy_RegistersDeviceHash_ButDoesNotGrantAccess()
    {
        var fake = new FakeLegacyClient(new AuthService.Services.Licensing.LegacyActivationResult { CodeValid = true, Registered = true });
        var storePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        var vm = NewVm(storePath);
        vm.UseLegacyActivation = true;
        vm.LegacyClientOverride = fake;
        vm.Code = "aWiS1Tbo2bm";

        await vm.ActivateAsync();

        // device hash sent is Hash(MachineGuid-stand-in), matching the token contract
        Assert.Equal(DeviceFingerprint.Hash("TEST-DEVICE"), fake.LastDevice);
        Assert.Equal("aWiS1Tbo2bm", fake.LastCode);
        // NOT granted: nothing stored, and this VM did not report a valid license
        Assert.Null(new AuthService.Services.Licensing.LicenseStore(storePath).Read());
        Assert.Contains("issued", vm.Status, StringComparison.OrdinalIgnoreCase); // "...will be issued shortly"
    }

    [Fact]
    public async Task Legacy_UnknownCode_ShowsError()
    {
        var fake = new FakeLegacyClient(new AuthService.Services.Licensing.LegacyActivationResult { CodeValid = false, Registered = false, Error = "Code not found" });
        var vm = NewVm(Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json"));
        vm.UseLegacyActivation = true;
        vm.LegacyClientOverride = fake;
        vm.Code = "nope";

        await vm.ActivateAsync();

        Assert.Contains("Code not found", vm.Status);
    }

    [Fact]
    public async Task Legacy_NeverSetsGlobalValid_ForFreshVmBaseline()
    {
        // A legacy registration must not touch the licensing store for this VM.
        var fake = new FakeLegacyClient(new AuthService.Services.Licensing.LegacyActivationResult { CodeValid = true, Registered = true });
        var storePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        var vm = NewVm(storePath);
        vm.UseLegacyActivation = true;
        vm.LegacyClientOverride = fake;
        vm.Code = "aWiS1Tbo2bm";

        await vm.ActivateAsync();

        Assert.Null(new AuthService.Services.Licensing.LicenseStore(storePath).Read());
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `dotnet test AuthService.Tests --filter ActivationRoutingTests`
Expected: FAIL — `UseLegacyActivation` / `LegacyClientOverride` not found.

- [ ] **Step 3: Implement**

In `AuthService/MVVM/ViewModel/AuthViewModel.cs`:

Add the seams near the other override properties (after `MintClientOverride`):
```csharp
        public ILegacyActivationClient LegacyClientOverride { get; set; }
        public bool UseLegacyActivation { get; set; }
```

Seed production defaults in the constructor (after the `MintClientOverride = ...` line):
```csharp
            LegacyClientOverride = new HttpLegacyActivationClient(
                new System.Net.Http.HttpClient(),
                ActivationEndpoints.MarketplaceRedemptionsUrl,
                ActivationEndpoints.MarketplaceRedeemUrl);
            UseLegacyActivation = !ActivationEndpoints.MintConfigured;
```

Route the code branch — replace the `case ActivationInputKind.Code` body in `ActivateAsync`:
```csharp
                case ActivationInputKind.Code:
                default:
                    if (UseLegacyActivation)
                        await RegisterLegacyAsync(raw);
                    else
                        await ActivateWithCodeAsync(raw);
                    return;
```

Add the new method (next to `ActivateWithCodeAsync`):
```csharp
        // Interim path used until the mint service is live: validate the code and register
        // this machine's device hash with the marketplace, then tell the user their license
        // is coming. Deliberately grants NO access - the provider mints tokens manually from
        // the registered hashes.
        private async Task RegisterLegacyAsync(string code)
        {
            IsLoading = true;
            ServerResponse = "Registering with the activation server...";
            Status = string.Empty;
            StatusForeground = System.Windows.Media.Brushes.Black;
            try
            {
                var deviceHash = DeviceFingerprint.Hash(DeviceOverride);
                var result = await LegacyClientOverride.RegisterAsync(code, deviceHash).ConfigureAwait(true);
                if (result != null && result.Registered)
                {
                    Status = "Your device has been registered. Your license will be issued shortly.";
                    StatusForeground = System.Windows.Media.Brushes.Green;
                    ServerResponse = "Device ID: " + deviceHash;
                }
                else
                {
                    Status = "Registration failed: " + (result?.Error ?? "no response");
                    StatusForeground = System.Windows.Media.Brushes.Red;
                    ServerResponse = string.Empty;
                }
            }
            finally { IsLoading = false; }
        }
```

- [ ] **Step 4: Run tests + full suite + multi-target build**

Run: `dotnet test AuthService.Tests --filter ActivationRoutingTests` → all PASS (existing + 3 new).
Run: `dotnet test AuthService.Tests` → all PASS.
Run each config explicitly (`-c "Net Framework 4.7"`, `-c "Net Framework 4.8.1"`, `-c "Net8.0-windows"`) → all succeed.

- [ ] **Step 5: Commit**

```bash
git add AuthService/MVVM/ViewModel/AuthViewModel.cs AuthService.Tests/ActivationRoutingTests.cs
git commit -m "feat: route code activation through legacy device-registration fallback until mint service is live

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- Sends the code the old way (GET redemptions) → Task 1 `RegisterAsync` GET. ✓
- Sends the device id only if the response is ok → Task 1: POST only when GET `success==true`. ✓
- Registers the device hash (the value the manual token must match) → Task 1 sends `data[]=DeviceFingerprint.Hash(...)`; Task 2 passes `Hash(DeviceOverride)`. ✓
- Grants no access → Task 2 `RegisterLegacyAsync` never calls `SetStatus(Valid)`/`store.Write`; tests assert store is null and no Valid. ✓
- Interim until the service is ready → routing gated on `ActivationEndpoints.MintConfigured`; flips to the real mint path automatically once `FIRSTOPTION_MINT_URL` is set. ✓

**Placeholder scan:** No TBD/TODO; all steps carry complete code.

**Type consistency:** `LegacyActivationResult{CodeValid,Registered,Error}`, `ILegacyActivationClient.RegisterAsync(code, deviceHash)`, `HttpLegacyActivationClient(HttpClient, redemptionsUrl, redeemUrl)`, `ActivationEndpoints.MarketplaceRedemptionsUrl/MarketplaceRedeemUrl/MintConfigured`, VM `LegacyClientOverride`/`UseLegacyActivation`/`RegisterLegacyAsync` are used consistently across both tasks.

**Invariant note:** the no-bypass invariant is preserved — the legacy path is terminal and never reaches `VerifyAndStore` or `SetStatus(Valid)`. The only routes to `Valid` remain the verified-token paths.
