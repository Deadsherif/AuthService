# Online + Offline Activation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the online activation path (paste code → add-in calls a mint service → stores the token) and a clean file-based offline path (a standalone device-capture tool → provider mints from a device file → buyer pastes a `.FO` file path), by making the existing single activation field auto-route between code, raw token, and `.FO` file.

**Architecture:** Restore the user's original single-field UI from branch `dev/OAuth` (one `Code` TextBox + a "Check" button bound to `SubmitCommand` + a `ServerResponse` status line) — replacing the subagent-built "Air-Gapped Activation / fingerprint / paste-token" layout currently on this branch. All new behavior is view-model routing behind `SubmitCommand`, plus two new standalone tools and one reference service. The add-in classifies whatever is typed into the one field: a `.FO` path is read as a minted token and verified locally; a JWT is verified locally; anything else is treated as a purchase code and sent to the mint endpoint. Device identity continues to be `SHA-256(MachineGuid)` exactly as `DeviceFingerprint` computes it today. The offline user never sees a fingerprint in the add-in — they run `OfflineActivationClient` separately to produce their device file.

**Tech Stack:** C# multi-target (net47/net48/net8.0-windows) for the add-in; net8.0 console tools (`OfflineActivationClient`, existing `LicenseMint`); net8.0 minimal-API reference service (`MintService`); xUnit tests; `System.IdentityModel.Tokens.Jwt` (already referenced).

## Global Constraints

- **UI = the user's original from `dev/OAuth`.** `AuthService/MVVM/View/AuthWindow.xaml` is *restored verbatim* from branch `dev/OAuth` (single `Code` field + "Check"/`SubmitCommand` + Close + `ServerResponse` line; NO fingerprint display, NO paste-token box, NO "Air-Gapped Activation" section). Do not redesign it. `AuthWindow.xaml.cs` stays the current minimal version (sets `DataContext` only — do NOT restore the `dev/OAuth` code-behind, which calls the removed `OnFirstOptionPremiseAuth` premise path). All routing lives in `AuthViewModel` behind `SubmitCommand`.
- **Device identity:** the device value is `DeviceFingerprint.Hash(DeviceFingerprint.CurrentDeviceId())` = lowercase-hex `SHA-256(MachineGuid)`. Every producer of a device value (the add-in, `OfflineActivationClient`) MUST produce this exact value. Parity anchor: `Hash("TEST-DEVICE") == 6be0412a5dac0a63d688a9a60608b2257c8292bb663738b952b9bbe5a4ff9fdd`.
- **Token contract unchanged:** JWT/ES256, claims `iss/addon/tier/iat/exp/device/jti`, header `kid`. The `device` claim is the hash above.
- **`.FO` convention:** the offline token file is a plaintext file whose content is the minted JWT; its name ends with `.FO` (case-insensitive). The add-in treats an entered value ending in `.FO` as a *path* to such a file.
- **Multi-target:** add-in code compiles on net47/net48/net8.0-windows. Build each config explicitly: `-c "Net Framework 4.7"`, `-c "Net Framework 4.8.1"`, `-c "Net8.0-windows"` (a bare `dotnet build` only builds the default config). New add-in source files go in the explicit `<Compile>` list in `AuthService.csproj` (`EnableDefaultCompileItems=false`).
- **Activation requires a currently-valid token:** activation (all three input kinds) accepts only `VerifyStatus.Valid` (not `Expired`), matching the current `ExecuteActivateToken` behavior.
- **Test command:** `dotnet test AuthService.Tests` builds cleanly as-is.

## File Structure

**New — standalone tools**
- `tools/OfflineActivationClient/OfflineActivationClient.csproj` + `Program.cs` + `DeviceId.cs` — buyer-run tool: writes `SHA-256(MachineGuid)` to a file.
- `tools/MintService/MintService.csproj` + `Program.cs` — reference self-hosted mint endpoint (`POST /activate`).

**Modified — tools**
- `tools/LicenseMint/Program.cs` — `mint` verb reads the device value from a file path.

**New — add-in (shipped)**
- `AuthService/Services/Licensing/ActivationInput.cs` — pure classifier: `Code | Token | TokenFile`.
- `AuthService/Services/Licensing/MintClient.cs` — `IMintClient` + `HttpMintClient` + `MintResult` + `ActivationEndpoints`.

**Restored — add-in (shipped)**
- `AuthService/MVVM/View/AuthWindow.xaml` — restored verbatim from `dev/OAuth` (single-field UI).

**Modified — add-in (shipped)**
- `AuthService/MVVM/ViewModel/AuthViewModel.cs` — expose the restored UI's bindings (`Code`, `SubmitCommand`, `ServerResponse`); remove the subagent-era `PastedToken`/`ActivateTokenCommand`/`DeviceFingerprintDisplay`; route activation by input kind behind `SubmitCommand`; add `IMintClient` seam; make activation async.
- `AuthService/AuthService.csproj` — add the two new `<Compile>` includes.

**New — tests**
- `AuthService.Tests/ActivationInputTests.cs`
- `AuthService.Tests/OfflineActivationClientParityTests.cs`
- `AuthService.Tests/MintClientTests.cs`
- `AuthService.Tests/ActivationRoutingTests.cs`
- `AuthService.Tests/AuthService.Tests.csproj` — add a `ProjectReference` to `OfflineActivationClient`.

---

## Task 1: OfflineActivationClient — capture device id to a file

**Files:**
- Create: `tools/OfflineActivationClient/OfflineActivationClient.csproj`
- Create: `tools/OfflineActivationClient/DeviceId.cs`
- Create: `tools/OfflineActivationClient/Program.cs`
- Modify: `AuthService.sln` (add project)

**Interfaces:**
- Produces: `static class OfflineActivationClient.DeviceId { string Sha256Hex(string s); string ReadMachineGuid(); string Compute(); }` where `Compute() == Sha256Hex(ReadMachineGuid())`.
- `Program` writes `Compute()` to a file (default `FirstOption-Device.txt` in the cwd, or `args[0]` if given) and prints the absolute path.

- [ ] **Step 1: Create the project**

`tools/OfflineActivationClient/OfflineActivationClient.csproj`:
```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0-windows</TargetFramework>
    <Nullable>disable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <AssemblyName>FirstOption-Activation</AssemblyName>
  </PropertyGroup>
</Project>
```
> `net8.0-windows` so the registry read is available; ship as a self-contained exe later if desired. The buyer double-clicks or runs it.

- [ ] **Step 2: Write the failing parity test** (in the add-in test project, so it can compare against `DeviceFingerprint`)

First add a project reference in `AuthService.Tests/AuthService.Tests.csproj` inside the existing `<ItemGroup>` that holds the AuthService reference:
```xml
<ProjectReference Include="..\tools\OfflineActivationClient\OfflineActivationClient.csproj" />
```

`AuthService.Tests/OfflineActivationClientParityTests.cs`:
```csharp
using AuthService.Services.Licensing;
using Xunit;

public class OfflineActivationClientParityTests
{
    [Fact]
    public void Sha256Hex_MatchesDeviceFingerprintHash()
    {
        // Both must produce the identical device value for the same input, or an
        // offline-minted token will never match the add-in's computed device id.
        Assert.Equal(
            DeviceFingerprint.Hash("TEST-DEVICE"),
            OfflineActivationClient.DeviceId.Sha256Hex("TEST-DEVICE"));

        Assert.Equal(
            "6be0412a5dac0a63d688a9a60608b2257c8292bb663738b952b9bbe5a4ff9fdd",
            OfflineActivationClient.DeviceId.Sha256Hex("TEST-DEVICE"));
    }
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `dotnet test AuthService.Tests --filter OfflineActivationClientParityTests`
Expected: FAIL — `OfflineActivationClient.DeviceId` not found.

- [ ] **Step 4: Implement `DeviceId` and `Program`**

`tools/OfflineActivationClient/DeviceId.cs`:
```csharp
using System.Security.Cryptography;
using System.Text;

namespace OfflineActivationClient
{
    public static class DeviceId
    {
        // MUST stay byte-identical to AuthService DeviceFingerprint.Hash / CurrentDeviceId.
        public static string Sha256Hex(string s)
        {
            if (s == null) s = string.Empty;
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(s));
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        public static string ReadMachineGuid()
        {
            try
            {
                using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
                return (k?.GetValue("MachineGuid") as string) ?? string.Empty;
            }
            catch { return string.Empty; }
        }

        public static string Compute() => Sha256Hex(ReadMachineGuid());
    }
}
```

`tools/OfflineActivationClient/Program.cs`:
```csharp
using OfflineActivationClient;

string outPath = args.Length > 0 ? args[0] : "FirstOption-Device.txt";
string device = DeviceId.Compute();
File.WriteAllText(outPath, device);
string full = Path.GetFullPath(outPath);
Console.WriteLine("First Option — device activation file created:");
Console.WriteLine("  " + full);
Console.WriteLine();
Console.WriteLine("Email this file to First Option to receive your license.");
return 0;
```

- [ ] **Step 5: Add to solution, run test, commit**

Run:
```bash
dotnet sln AuthService.sln add tools/OfflineActivationClient/OfflineActivationClient.csproj
dotnet test AuthService.Tests --filter OfflineActivationClientParityTests
```
Expected: PASS.
```bash
git add tools/OfflineActivationClient AuthService.Tests/OfflineActivationClientParityTests.cs AuthService.Tests/AuthService.Tests.csproj AuthService.sln
git commit -m "feat: OfflineActivationClient device-capture tool"
```

---

## Task 2: LicenseMint `mint` reads the device from a file

**Files:**
- Modify: `tools/LicenseMint/Program.cs` (the `mint` verb only)

**Interfaces:**
- Changes the `mint` verb args from `... <device>` to `... <deviceFilePath>`: the last argument is now a path to the file produced by `OfflineActivationClient` (or any file whose first non-empty line is the device hash). The internal `Mint(...)` helper and the `vectors` verb are unchanged.

- [ ] **Step 1: Read the current mint verb**

Read `tools/LicenseMint/Program.cs` lines 22-41 (the `case "mint"` block) so the edit is precise.

- [ ] **Step 2: Replace the `mint` verb body**

Replace the `case "mint":` block with:
```csharp
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
```

- [ ] **Step 3: Manually verify the round trip**

Run (Git Bash):
```bash
cd /tmp && rm -rf mtest && mkdir mtest && cd mtest
dotnet run --project "D:/AhmedRashad/FirstOption/FirstOption/AuthService-Remake/tools/LicenseMint" -- keygen
# extract private key
python - <<'PY'
import json
open("private.pem","w").write(json.load(open("keys.json"))["privateKeyPem"])
PY
printf '6be0412a5dac0a63d688a9a60608b2257c8292bb663738b952b9bbe5a4ff9fdd\n' > device.txt
dotnet run --project "D:/AhmedRashad/FirstOption/FirstOption/AuthService-Remake/tools/LicenseMint" -- mint ./private.pem k1 "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8" paid 1700000000 1900000000 ./device.txt
```
Expected: the last output line is a `eyJ...` JWT (three dot-separated segments). Confirm it has three segments.

- [ ] **Step 4: Confirm `vectors` still works (device helper unchanged)**

Run: `dotnet run --project tools/LicenseMint -- vectors` (from a dir containing a `keys.json`) → prints `wrote vectors.json`.

- [ ] **Step 5: Commit**

```bash
git add tools/LicenseMint/Program.cs
git commit -m "feat: LicenseMint mint reads device value from a file path"
```

---

## Task 3: Activation input classifier

**Files:**
- Create: `AuthService/Services/Licensing/ActivationInput.cs`
- Modify: `AuthService/AuthService.csproj`
- Test: `AuthService.Tests/ActivationInputTests.cs`

**Interfaces:**
- Produces:
  - `enum ActivationInputKind { Code, Token, TokenFile }`
  - `static class ActivationInput { static ActivationInputKind Classify(string raw); }`
- Rules (applied to the trimmed input): ends with `.FO` (OrdinalIgnoreCase) → `TokenFile`; else looks like a JWT (contains exactly two `.` and starts with `eyJ`) → `Token`; else → `Code`.

- [ ] **Step 1: Write the failing tests**

`AuthService.Tests/ActivationInputTests.cs`:
```csharp
using AuthService.Services.Licensing;
using Xunit;

public class ActivationInputTests
{
    [Theory]
    [InlineData(@"C:\Users\me\license.FO", ActivationInputKind.TokenFile)]
    [InlineData(@"C:\Users\me\LICENSE.fo", ActivationInputKind.TokenFile)]
    [InlineData("  D:\\path\\x.FO  ", ActivationInputKind.TokenFile)]
    [InlineData("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJmbyJ9.sig", ActivationInputKind.Token)]
    [InlineData("aWiS1Tbo2bm", ActivationInputKind.Code)]
    [InlineData("ABC-123", ActivationInputKind.Code)]
    public void Classify_ReturnsExpectedKind(string raw, ActivationInputKind expected)
    {
        Assert.Equal(expected, ActivationInput.Classify(raw));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `dotnet test AuthService.Tests --filter ActivationInputTests`
Expected: FAIL — type not found.

- [ ] **Step 3: Implement**

`AuthService/Services/Licensing/ActivationInput.cs`:
```csharp
using System;

namespace AuthService.Services.Licensing
{
    public enum ActivationInputKind { Code, Token, TokenFile }

    public static class ActivationInput
    {
        public static ActivationInputKind Classify(string raw)
        {
            var s = (raw ?? string.Empty).Trim();
            if (s.EndsWith(".FO", StringComparison.OrdinalIgnoreCase))
                return ActivationInputKind.TokenFile;
            if (s.StartsWith("eyJ", StringComparison.Ordinal) && CountDots(s) == 2)
                return ActivationInputKind.Token;
            return ActivationInputKind.Code;
        }

        private static int CountDots(string s)
        {
            int n = 0;
            foreach (var c in s) if (c == '.') n++;
            return n;
        }
    }
}
```
Add to `AuthService.csproj` `<Compile>` list:
```xml
<Compile Include="Services\Licensing\ActivationInput.cs" />
```

- [ ] **Step 4: Run + multi-target build**

Run: `dotnet test AuthService.Tests --filter ActivationInputTests` → PASS.
Run the three explicit-config builds → all succeed.

- [ ] **Step 5: Commit**

```bash
git add AuthService/Services/Licensing/ActivationInput.cs AuthService/AuthService.csproj AuthService.Tests/ActivationInputTests.cs
git commit -m "feat: activation input classifier (code/token/.FO file)"
```

---

## Task 4: Restore original UI + rewire view model to a single-field router

**Files:**
- Restore: `AuthService/MVVM/View/AuthWindow.xaml` (verbatim from `dev/OAuth`)
- Modify: `AuthService/MVVM/ViewModel/AuthViewModel.cs`
- Test: `AuthService.Tests/ActivationRoutingTests.cs` (create; more cases added in Task 6)

**Interfaces:**
- Consumes: `ActivationInput.Classify`, `LicenseTokenVerifier`, `DeviceFingerprint`, `LicenseStore`, `StoredLicense`.
- The restored XAML binds these view-model members, which MUST exist (or bindings silently fail at runtime): `Code` (string, two-way), `SubmitCommand` (ICommand, the "Check" button), `ServerResponse` (string), plus the already-present `CloseCommand`, `CloseButtonText`, `Status`, `StatusForeground`, `EndDate`, `IsLoading`, `SignupLinkVisibility`, `OpenSignupLinkCommand`, `SignupLink`.
- Produces on `AuthViewModel`:
  - `string Code { get; set; }` — the single input field; setter raises `SubmitCommand` re-evaluation.
  - `string ServerResponse { get; set; }` — transient status line.
  - `ICommand SubmitCommand { get; }` — "Check" button; handler is an `async void` wrapper over `ActivateAsync`.
  - `internal Task ActivateAsync()` — the testable activation entry point; routes `Code` by input kind (online branch stubbed here, implemented in Task 6).
  - `private void VerifyAndStore(string token)` — verify → addon → device → store (moved from the current `ExecuteActivateToken`).
- Removes from `AuthViewModel` (the subagent-era members the restored UI does not bind): `PastedToken`, `ActivateTokenCommand`, `CanExecuteActivateToken`, `ExecuteActivateToken`, `DeviceFingerprintDisplay`, and the `_pastedToken` field.
- Behavior by input kind (on `Code`): `TokenFile` → read the file as the token → `VerifyAndStore`; `Token` → `VerifyAndStore(Code)`; `Code` → (Task 6) mint call. Missing `.FO` file → `Status = "Activation failed: file not found"`.

- [ ] **Step 1: Restore the original UI XAML**

Run:
```bash
git checkout dev/OAuth -- AuthService/MVVM/View/AuthWindow.xaml
```
Do NOT touch `AuthWindow.xaml.cs` — the current version (sets `DataContext` only) is correct; the `dev/OAuth` code-behind calls the removed `OnFirstOptionPremiseAuth` and must not be restored.

- [ ] **Step 2: Write the failing tests**

`AuthService.Tests/ActivationRoutingTests.cs`:
```csharp
using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using AuthService.MVVM.ViewModel;
using AuthService.Services.Licensing;
using Xunit;

public class ActivationRoutingTests
{
    private static string ValidToken()
    {
        var keys = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/keys.json"));
        LicensePublicKeys.LoadForTests(keys.GetProperty("kid").GetString(), keys.GetProperty("publicKeyPem").GetString());
        var vectors = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("Vectors/vectors.json"));
        foreach (var v in vectors.EnumerateArray())
            if (v.GetProperty("name").GetString() == "valid") return v.GetProperty("token").GetString();
        throw new Exception("valid vector missing");
    }

    private static AuthViewModel NewVm(string storePath) =>
        new AuthViewModel("Addin", "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8")
        {
            TokenStoreOverride = new LicenseStore(storePath),
            NowOverride = DateTimeOffset.FromUnixTimeSeconds(1_750_000_000),
            DeviceOverride = "TEST-DEVICE",
        };

    [Fact]
    public async Task RawToken_Activates()
    {
        var vm = NewVm(Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json"));
        vm.Code = ValidToken();
        await vm.ActivateAsync();
        Assert.Equal(AuthService.Services.SubscriptionService.SubscriptionStatus.Valid,
                     AuthService.Services.SubscriptionService.Status);
    }

    [Fact]
    public async Task FoFile_Activates()
    {
        var foPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".FO");
        File.WriteAllText(foPath, ValidToken());
        var vm = NewVm(Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json"));
        vm.Code = foPath;
        await vm.ActivateAsync();
        Assert.Equal(AuthService.Services.SubscriptionService.SubscriptionStatus.Valid,
                     AuthService.Services.SubscriptionService.Status);
    }

    [Fact]
    public async Task FoFile_Missing_FailsCleanly()
    {
        var vm = NewVm(Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json"));
        vm.Code = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".FO"); // does not exist
        await vm.ActivateAsync();
        Assert.Contains("file not found", vm.Status);
    }
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `dotnet test AuthService.Tests --filter ActivationRoutingTests`
Expected: FAIL — `Code` / `ActivateAsync` not found (the current VM has `PastedToken`/`ActivateAsync` absent).

- [ ] **Step 4: Rewire `AuthViewModel`**

In `AuthService/MVVM/ViewModel/AuthViewModel.cs`:

(a) Add `using System.Threading.Tasks;` at the top.

(b) Remove these members entirely: the `_pastedToken` field, `PastedToken` property, `DeviceFingerprintDisplay` property, `ActivateTokenCommand` property, `CanExecuteActivateToken`, and the current `ExecuteActivateToken` method.

(c) Add the `Code` and `ServerResponse` backing fields + properties, and a `SubmitCommand`:
```csharp
        private string _code;
        public string Code
        {
            get => _code;
            set
            {
                if (SetProperty(ref _code, value))
                    ((RelayCommand)SubmitCommand).RaiseCanExecuteChanged();
            }
        }

        private string _serverResponse;
        public string ServerResponse
        {
            get => _serverResponse;
            set => SetProperty(ref _serverResponse, value);
        }

        public ICommand SubmitCommand { get; }
```

(d) In the constructor, wire the command (replace the removed `ActivateTokenCommand = ...` line):
```csharp
            SubmitCommand = new RelayCommand(ExecuteSubmit, CanExecuteSubmit);
```
(Keep the existing `TokenStoreOverride`/`NowOverride`/`DeviceOverride` default assignments.)

(e) Add the handler, async core, stub, and the verify/store helper:
```csharp
        private bool CanExecuteSubmit(object parameter) =>
            !string.IsNullOrWhiteSpace(Code) && !IsLoading;

        private async void ExecuteSubmit(object parameter)
        {
            try { await ActivateAsync(); }
            catch (Exception)
            {
                Status = "Activation error";
                StatusForeground = System.Windows.Media.Brushes.Red;
            }
            finally { IsLoading = false; }
        }

        internal async Task ActivateAsync()
        {
            if (string.IsNullOrWhiteSpace(Code))
            {
                Status = "Enter your license code, token, or .FO file path";
                StatusForeground = System.Windows.Media.Brushes.Red;
                return;
            }

            var raw = Code.Trim();
            switch (ActivationInput.Classify(raw))
            {
                case ActivationInputKind.TokenFile:
                {
                    if (!System.IO.File.Exists(raw))
                    {
                        Status = "Activation failed: file not found";
                        StatusForeground = System.Windows.Media.Brushes.Red;
                        return;
                    }
                    VerifyAndStore(System.IO.File.ReadAllText(raw).Trim());
                    return;
                }

                case ActivationInputKind.Token:
                    VerifyAndStore(raw);
                    return;

                case ActivationInputKind.Code:
                default:
                    await ActivateWithCodeAsync(raw); // online path — Task 6 implements this
                    return;
            }
        }

        // Task 6 replaces this stub with a real mint-endpoint call.
        private Task ActivateWithCodeAsync(string code)
        {
            Status = "Online activation is not available yet";
            StatusForeground = System.Windows.Media.Brushes.Red;
            return Task.CompletedTask;
        }

        private void VerifyAndStore(string token)
        {
            var verifier = new LicenseTokenVerifier();
            var result = verifier.Verify(token, NowOverride);

            if (result.Status != VerifyStatus.Valid)
            {
                Status = "Activation failed: token is invalid or expired";
                StatusForeground = System.Windows.Media.Brushes.Red;
                return;
            }

            var claims = result.Claims;

            if (!string.IsNullOrEmpty(_guid) &&
                !string.Equals(claims.AddonId, _guid, StringComparison.OrdinalIgnoreCase))
            {
                Status = "Activation failed: token is not for this add-in";
                StatusForeground = System.Windows.Media.Brushes.Red;
                return;
            }

            if (!DeviceFingerprint.Matches(claims.DeviceHash, DeviceOverride))
            {
                Status = "Activation failed: token was minted for a different device";
                StatusForeground = System.Windows.Media.Brushes.Red;
                return;
            }

            var store = TokenStoreOverride ?? LicenseStore.Default();
            var seededFloor = claims.IssuedAt > NowOverride ? claims.IssuedAt : NowOverride;
            store.Write(new StoredLicense { Token = token, MaxDateSeen = seededFloor });

            SubscriptionService.SetStatus(SubscriptionService.SubscriptionStatus.Valid);
            EndDate = claims.Expires.UtcDateTime;
            ServerResponse = string.Empty;
            Status = "Activated - Valid";
            StatusForeground = System.Windows.Media.Brushes.Green;
            CloseButtonText = "Continue";
            ((RelayCommand)CloseCommand).RaiseCanExecuteChanged();
        }
```

> Update any existing test that referenced `PastedToken` / `ActivateTokenCommand` / `DeviceFingerprintDisplay` (search the test project) to use `Code` and `await vm.ActivateAsync()`. Delete assertions on the removed `DeviceFingerprintDisplay`.

- [ ] **Step 5: Run tests + multi-target build, then commit**

Run: `dotnet test AuthService.Tests --filter ActivationRoutingTests` → 3 PASS.
Run: `dotnet test AuthService.Tests` → all PASS (fix any updated call sites).
Run the three explicit-config builds → all succeed.
```bash
git add AuthService/MVVM AuthService.Tests
git commit -m "feat: restore original single-field UI; route activation by input kind (.FO/token/code)"
```

---

## Task 5: Mint client (HTTP)

**Files:**
- Create: `AuthService/Services/Licensing/MintClient.cs`
- Modify: `AuthService/AuthService.csproj`
- Test: `AuthService.Tests/MintClientTests.cs`

**Interfaces:**
- Produces:
  - `sealed class MintResult { bool Success; string Token; string Error; }`
  - `interface IMintClient { Task<MintResult> RequestTokenAsync(string code, string deviceId); }`
  - `sealed class HttpMintClient : IMintClient` — constructor `HttpMintClient(HttpClient http, string url)`; POSTs JSON `{"code":..., "device":...}`, expects `200` with `{"token":"..."}` (success) or any non-2xx / `{"error":"..."}` (failure).
  - `static class ActivationEndpoints { static string MintUrl { get; } }` — from env var `FIRSTOPTION_MINT_URL`, else the placeholder `"https://REPLACE-ME.invalid/activate"`.

- [ ] **Step 1: Write the failing test** (drives `HttpMintClient` with a stub handler — no network)

`AuthService.Tests/MintClientTests.cs`:
```csharp
using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AuthService.Services.Licensing;
using Xunit;

public class MintClientTests
{
    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _code;
        private readonly string _body;
        public string LastRequestBody { get; private set; }
        public StubHandler(HttpStatusCode code, string body) { _code = code; _body = body; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            LastRequestBody = request.Content == null ? null : await request.Content.ReadAsStringAsync();
            return new HttpResponseMessage(_code) { Content = new StringContent(_body) };
        }
    }

    [Fact]
    public async Task Success_ReturnsToken_AndSendsCodeAndDevice()
    {
        var handler = new StubHandler(HttpStatusCode.OK, "{\"token\":\"eyJ.a.b\"}");
        var client = new HttpMintClient(new HttpClient(handler), "https://mint.example/activate");
        var result = await client.RequestTokenAsync("aWiS1Tbo2bm", "devhash123");
        Assert.True(result.Success);
        Assert.Equal("eyJ.a.b", result.Token);
        Assert.Contains("aWiS1Tbo2bm", handler.LastRequestBody);
        Assert.Contains("devhash123", handler.LastRequestBody);
    }

    [Fact]
    public async Task HttpError_ReturnsFailure()
    {
        var client = new HttpMintClient(new HttpClient(new StubHandler(HttpStatusCode.BadRequest, "{\"error\":\"bad code\"}")),
                                        "https://mint.example/activate");
        var result = await client.RequestTokenAsync("nope", "devhash123");
        Assert.False(result.Success);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `dotnet test AuthService.Tests --filter MintClientTests`
Expected: FAIL — types not found.

- [ ] **Step 3: Implement**

`AuthService/Services/Licensing/MintClient.cs`:
```csharp
using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace AuthService.Services.Licensing
{
    public sealed class MintResult
    {
        public bool Success { get; set; }
        public string Token { get; set; }
        public string Error { get; set; }
    }

    public interface IMintClient
    {
        Task<MintResult> RequestTokenAsync(string code, string deviceId);
    }

    public static class ActivationEndpoints
    {
        public static string MintUrl =>
            Environment.GetEnvironmentVariable("FIRSTOPTION_MINT_URL") ?? "https://REPLACE-ME.invalid/activate";
    }

    public sealed class HttpMintClient : IMintClient
    {
        private readonly HttpClient _http;
        private readonly string _url;

        public HttpMintClient(HttpClient http, string url) { _http = http; _url = url; }

        public async Task<MintResult> RequestTokenAsync(string code, string deviceId)
        {
            try
            {
                var payload = JsonSerializer.Serialize(new { code, device = deviceId });
                using var content = new StringContent(payload, Encoding.UTF8, "application/json");
                using var response = await _http.PostAsync(_url, content).ConfigureAwait(false);
                var body = response.Content == null ? string.Empty : await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                    return new MintResult { Success = false, Error = "Server rejected the code (" + (int)response.StatusCode + ")" };

                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("token", out var t) && t.ValueKind == JsonValueKind.String)
                    return new MintResult { Success = true, Token = t.GetString() };

                return new MintResult { Success = false, Error = "Server did not return a token" };
            }
            catch (Exception ex)
            {
                return new MintResult { Success = false, Error = "Could not reach the activation server: " + ex.Message };
            }
        }
    }
}
```
Add to `AuthService.csproj` `<Compile>` list:
```xml
<Compile Include="Services\Licensing\MintClient.cs" />
```

- [ ] **Step 4: Run tests + multi-target build**

Run: `dotnet test AuthService.Tests --filter MintClientTests` → 2 PASS.
Run the three explicit-config builds → all succeed. (`System.Net.Http` is available on all three TFMs.)

- [ ] **Step 5: Commit**

```bash
git add AuthService/Services/Licensing/MintClient.cs AuthService/AuthService.csproj AuthService.Tests/MintClientTests.cs
git commit -m "feat: HTTP mint client for online activation"
```

---

## Task 6: Wire the online (code) branch

**Files:**
- Modify: `AuthService/MVVM/ViewModel/AuthViewModel.cs`
- Test: `AuthService.Tests/ActivationRoutingTests.cs` (add online cases)

**Interfaces:**
- Consumes: `IMintClient`, `MintResult`, `ActivationEndpoints`, `HttpMintClient`.
- Produces on `AuthViewModel`:
  - `public IMintClient MintClientOverride { get; set; }` — test seam; production default constructed in the constructor as `new HttpMintClient(new HttpClient(), ActivationEndpoints.MintUrl)`.
  - `ActivateWithCodeAsync(code)` (replacing the Task 4 stub): calls the mint client with `(code, DeviceOverride)`, and on success routes the returned token through `VerifyAndStore`.

- [ ] **Step 1: Write the failing tests** (fake `IMintClient` returns a real minted valid token)

Add to `AuthService.Tests/ActivationRoutingTests.cs`:
```csharp
    private sealed class FakeMintClient : AuthService.Services.Licensing.IMintClient
    {
        private readonly AuthService.Services.Licensing.MintResult _r;
        public string LastCode; public string LastDevice;
        public FakeMintClient(AuthService.Services.Licensing.MintResult r) { _r = r; }
        public Task<AuthService.Services.Licensing.MintResult> RequestTokenAsync(string code, string deviceId)
        { LastCode = code; LastDevice = deviceId; return Task.FromResult(_r); }
    }

    [Fact]
    public async Task Code_CallsMint_AndActivatesReturnedToken()
    {
        var fake = new FakeMintClient(new AuthService.Services.Licensing.MintResult { Success = true, Token = ValidToken() });
        var vm = NewVm(Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json"));
        vm.MintClientOverride = fake;
        vm.Code = "aWiS1Tbo2bm";
        await vm.ActivateAsync();
        Assert.Equal("aWiS1Tbo2bm", fake.LastCode);
        Assert.Equal("TEST-DEVICE", fake.LastDevice);
        Assert.Equal(AuthService.Services.SubscriptionService.SubscriptionStatus.Valid,
                     AuthService.Services.SubscriptionService.Status);
    }

    [Fact]
    public async Task Code_MintFails_ShowsError()
    {
        var fake = new FakeMintClient(new AuthService.Services.Licensing.MintResult { Success = false, Error = "bad code" });
        var vm = NewVm(Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json"));
        vm.MintClientOverride = fake;
        vm.Code = "nope";
        await vm.ActivateAsync();
        Assert.Contains("bad code", vm.Status);
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `dotnet test AuthService.Tests --filter ActivationRoutingTests`
Expected: FAIL — `MintClientOverride` not found.

- [ ] **Step 3: Implement**

In `AuthService/MVVM/ViewModel/AuthViewModel.cs`:

(a) Add the field + property and a production default in the constructor:
```csharp
        public IMintClient MintClientOverride { get; set; }
```
In the constructor, after the other defaults:
```csharp
            MintClientOverride = new HttpMintClient(new System.Net.Http.HttpClient(), ActivationEndpoints.MintUrl);
```

(b) Replace the `ActivateWithCodeAsync` stub with:
```csharp
        private async Task ActivateWithCodeAsync(string code)
        {
            IsLoading = true;
            ServerResponse = "Contacting activation server...";
            Status = string.Empty;
            StatusForeground = System.Windows.Media.Brushes.Black;
            try
            {
                var result = await MintClientOverride.RequestTokenAsync(code, DeviceOverride).ConfigureAwait(true);
                if (result == null || !result.Success)
                {
                    ServerResponse = string.Empty;
                    Status = "Activation failed: " + (result?.Error ?? "no response");
                    StatusForeground = System.Windows.Media.Brushes.Red;
                    return;
                }
                VerifyAndStore(result.Token);
            }
            finally { IsLoading = false; }
        }
```

- [ ] **Step 4: Run tests + multi-target build**

Run: `dotnet test AuthService.Tests --filter ActivationRoutingTests` → all PASS (5 cases).
Run: `dotnet test AuthService.Tests` → all PASS.
Run the three explicit-config builds → all succeed.

- [ ] **Step 5: Commit**

```bash
git add AuthService/MVVM/ViewModel/AuthViewModel.cs AuthService.Tests/ActivationRoutingTests.cs
git commit -m "feat: online activation — code branch calls mint endpoint and stores token"
```

---

## Task 7: Reference mint service (self-hosted)

**Files:**
- Create: `tools/MintService/MintService.csproj`
- Create: `tools/MintService/Program.cs`
- Modify: `AuthService.sln`
- Create: `docs/backend/mint-service-README.md`

**Interfaces:**
- Produces an HTTP service: `POST /activate` with body `{"code":"...","device":"..."}` → `200 {"token":"..."}` on success, `400 {"error":"..."}` on an invalid code. This is the endpoint `HttpMintClient` targets. It is a *reference* you self-host; it holds the private key and validates the code against the marketplace.

- [ ] **Step 1: Create the project**

`tools/MintService/MintService.csproj`:
```xml
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>disable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="8.1.2" />
    <PackageReference Include="Microsoft.IdentityModel.Tokens" Version="8.1.2" />
  </ItemGroup>
</Project>
```

- [ ] **Step 2: Implement the service**

`tools/MintService/Program.cs`:
```csharp
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
```

- [ ] **Step 3: Add to solution and smoke-test locally**

Run:
```bash
dotnet sln AuthService.sln add tools/MintService/MintService.csproj
dotnet build tools/MintService
```
Expected: build succeeds. (A live end-to-end run requires the env vars above and marketplace reachability; the add-in side is already covered by the `FakeMintClient` tests in Task 6, so no live call is required to land this task.)

- [ ] **Step 4: Write the operator README**

`docs/backend/mint-service-README.md` — document: the four env vars, that the private key never ships, the `POST /activate` contract (`{code,device}` → `{token}` / `{error}`), that the add-in reaches it via `FIRSTOPTION_MINT_URL`, and that this service is the one piece First Option self-hosts (HTTPS required in production). No marketplace credentials are needed because the redemptions endpoint is unauthenticated.

- [ ] **Step 5: Commit**

```bash
git add tools/MintService AuthService.sln docs/backend/mint-service-README.md
git commit -m "feat: reference self-hosted mint service (POST /activate)"
```

---

## Self-Review

**Spec coverage:**
- OfflineActivationClient produces hashed device id to a file → Task 1. ✓
- LicenseMint accepts a device *file path* → Task 2. ✓
- Field accepts tokens or file destinations; `.FO` path → read file, verify as token → Tasks 3, 4. ✓
- `.FO` detection ("if the add-in sees a file it is a minted token and tries to verify it") → Tasks 3, 4. ✓
- Full online path (client + endpoint) → Tasks 5, 6, 7. ✓
- UI = user's original from `dev/OAuth` (single `Code` field + Check), subagent air-gapped/fingerprint layout removed → Task 4 restores the XAML and rewires the VM to `Code`/`SubmitCommand`/`ServerResponse`. ✓
- Device parity between the standalone tool and the add-in → Task 1 parity test. ✓

**Placeholder scan:** No TBD/TODO. Task 4 ships a deliberate, named stub (`ActivateWithCodeAsync`) that Task 6 replaces — the stub has complete code and a passing behavior (clear error), so it is not an empty placeholder. Every code step carries real code.

**Type consistency:** `ActivationInputKind {Code,Token,TokenFile}`, `ActivationInput.Classify`, `IMintClient.RequestTokenAsync(code, deviceId)`, `MintResult{Success,Token,Error}`, `HttpMintClient(HttpClient,string)`, `AuthViewModel.ActivateAsync/MintClientOverride/VerifyAndStore`, `OfflineActivationClient.DeviceId.Sha256Hex/Compute` are used consistently across tasks. Device value semantics (`SHA-256(MachineGuid)` hex) match `DeviceFingerprint` and the committed vectors.

**Open risk:** the reference `MintService` (Task 7) uses `end_date` from the marketplace subscription payload as `exp`; if the real payload shape differs, adjust `ValidateCodeAsync` — flagged in its README. The add-in side does not depend on the service being live (Task 6 tests use a fake client).
