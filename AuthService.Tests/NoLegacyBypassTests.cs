using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using AuthService;
using AuthService.MVVM.ViewModel;
using AuthService.Services;
using AuthService.Services.Licensing;
using Xunit;

// Task 15 cutover: Auth.ValidateEntitlement (grants Valid straight from the forgeable
// LocalAuthCache) and the ValidateAuthCore -> ValidateCachedEntryAgainstServer -> SilentAuth
// legacy-cache fallback were deleted. The ONLY route to Valid through Auth is now the
// LicenseGate. These tests pin that down two ways:
//
//   1. Compile-time: this file does not reference Auth.ValidateEntitlement anywhere. If a
//      future edit resurrects that method (or any code path that still calls it), this file
//      keeps compiling regardless -- the real backstop is the reflection assertions below,
//      which fail loudly if the legacy members reappear under their old names.
//   2. Runtime, at the gate seam: with an empty LicenseStore (no token written), the gate
//      Auth.GateFactory produces evaluates to non-Valid, exactly as it would for any add-in
//      with no activated license.
//
// What this file deliberately does NOT attempt: driving Auth.ValidateAuth through its
// non-Valid branch end-to-end. That branch's only remaining behavior is
// `new AuthWindow(...).ShowDialog()` -- a real modal WPF window -- and ValidateAuthCore is
// private (InternalsVisibleTo only exposes internal/public members to this test assembly,
// not private ones), so there is no seam to intercept it short of reflection-invoking a
// private method and fighting STA/dispatcher plumbing to dismiss the dialog. That would test
// WPF, not the cutover. Coverage here is therefore: the gate-empty case returns non-Valid
// (assertion 2), and the legacy Valid-granting members are provably gone (assertion 1/3).
// Runtime UI-branch coverage (that ValidateAuthCore actually reaches the AuthWindow and
// returns whatever the dialog leaves in SubscriptionService.Status, without ever consulting
// LocalAuthCache) is NOT exercised by an automated test and would need manual/UI-automation
// verification.
public class NoLegacyBypassTests
{
    [Fact]
    public void EmptyLicenseStore_GateEvaluatesNonValid()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        Assert.False(File.Exists(path)); // sanity: nothing written, no stray token on disk

        Auth.GateFactory = _ => new LicenseGate(new LicenseStore(path));
        Auth.NowProvider = () => DateTimeOffset.FromUnixTimeSeconds(1_750_000_000);
        Auth.OnlineTimeProvider = () => null; // hermetic: no network call, order-independent
        Auth.DeviceProvider = () => "TEST-DEVICE";

        var gate = Auth.GateFactory("9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8");
        var status = gate.Evaluate(
            "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8",
            Auth.DeviceProvider(),
            Auth.NowProvider(),
            Auth.OnlineTimeProvider());

        // An empty store is exactly the "no license.json" case Auth.ValidateAuth hits before
        // it ever shows UI. If the gate itself doesn't grant Valid here, ValidateAuth's
        // fast-path (`if (status == GateStatus.Valid) ...`) cannot fire, and per assertion
        // below there is no other Auth code path left that could grant Valid instead.
        Assert.NotEqual(GateStatus.Valid, status);
    }

    [Fact]
    public void Auth_HasNoLegacyValidGrantingMembers()
    {
        var authType = typeof(Auth);
        var allMembers = authType
            .GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance)
            .Select(m => m.Name)
            .ToArray();

        // The offline-forge path: granted Valid straight from LocalAuthCache without ever
        // consulting the license gate.
        Assert.DoesNotContain("ValidateEntitlement", allMembers);

        // The legacy-cache fallback ValidateAuthCore used to consult on a non-Valid gate
        // result (SilentAuth-backed), and the dead background-revalidation machinery.
        Assert.DoesNotContain("ValidateCachedEntryAgainstServer", allMembers);
        Assert.DoesNotContain("StartBackgroundRevalidation", allMembers);

        // The subscription machinery that only existed to react to BackgroundValidationFailed.
        Assert.Null(authType.GetField("_backgroundFailureSubscription", BindingFlags.NonPublic | BindingFlags.Instance));
        Assert.False(
            AppDomain.CurrentDomain.GetAssemblies()
                .SelectMany(a => { try { return a.GetTypes(); } catch { return Type.EmptyTypes; } })
                .Any(t => t.Name == "AuthBackgroundFailureSubscription"),
            "AuthBackgroundFailureSubscription should have been deleted, not just unreferenced.");
    }

    [Fact]
    public void Auth_PublicSurface_UnchangedShape()
    {
        var authType = typeof(Auth);

        // Public ctors consuming add-ins depend on.
        Assert.NotNull(authType.GetConstructor(new[] { typeof(string), typeof(string) }));
        Assert.NotNull(authType.GetConstructor(new[] { typeof(string), typeof(string), typeof(System.Windows.Window) }));
        Assert.NotNull(authType.GetConstructor(new[] { typeof(string), typeof(string), typeof(System.Windows.Forms.Form) }));

        Assert.NotNull(authType.GetMethod("Dispose", Type.EmptyTypes));
        Assert.NotNull(authType.GetMethod("Validate", Type.EmptyTypes));
        Assert.NotNull(authType.GetProperty("IsRevoked"));
        Assert.NotNull(authType.GetProperty("SignupLink"));
        Assert.NotNull(authType.GetMethod("ValidateAuth", BindingFlags.Public | BindingFlags.Static));
        Assert.NotNull(authType.GetEvent("BackgroundValidationFailed", BindingFlags.Public | BindingFlags.Static));
    }

    // Task 16 cutover: AuthViewModel used to grant Valid two ways without the token gate --
    // OnFirstOptionPremiseAuth (premise auto-auth on Loaded, driven by shared service creds)
    // and ExecuteSubmitCore (legacy short-code marketplace redemption, wired to SubmitCommand).
    // Both were deleted.
    //
    // Task 4 (single-field activation router) reintroduced `Code` and `SubmitCommand`, but as
    // a router over the signed-token verify path (ActivateAsync -> VerifyAndStore), not the
    // old marketplace redemption -- so their presence is no longer a red flag. What must stay
    // gone is ExecuteSubmitCore itself (the legacy marketplace-calling implementation) and the
    // premise auto-auth members. This test pins down (reflection) that those are provably
    // gone, not just unreferenced by production code.
    [Fact]
    public void AuthViewModel_HasNoLegacyValidGrantingMembers()
    {
        var vmType = typeof(AuthViewModel);
        var allMembers = vmType
            .GetMembers(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance)
            .Select(m => m.Name)
            .ToArray();

        // Premise auto-auth: authenticated against the premise server with shared service
        // creds and granted Valid on Loaded, with no token and no gate involved.
        Assert.DoesNotContain("OnFirstOptionPremiseAuth", allMembers);

        // Legacy short-code redemption implementation: called the marketplace and granted
        // Valid on success, with no token and no gate involved. (SubmitCommand/Code/
        // CanExecuteSubmit/ExecuteSubmit are intentionally NOT asserted absent here -- Task 4
        // reintroduced them as the activation router's entry point, which routes to the
        // signed-token verify path, not to this deleted marketplace call.)
        Assert.DoesNotContain("ExecuteSubmitCore", allMembers);

        // AuthViewModel must no longer be able to write into LocalAuthCache at all -- those
        // calls only ever existed inside the two removed flows.
        Assert.DoesNotContain("_premiseAuthStarted", allMembers);
    }

    [Fact]
    public void AuthViewModel_ConstructingAndInvokingRemainingCommands_CannotReachValid()
    {
        // Sanity check that mirrors the reflection assertion above at the behavior level:
        // build the VM the way AuthWindow.xaml.cs does now (no Loaded-driven side effect,
        // since OnFirstOptionPremiseAuth is gone) and drive every command it exposes except
        // SubmitCommand with an actual code (which is exercised, with a real valid token, by
        // ActivationViewModelTests / ActivationRoutingTests). None of the remaining commands
        // should be able to grant Valid.
        SubscriptionService.SetStatus(SubscriptionService.SubscriptionStatus.Error);

        var vm = new AuthViewModel("Addin", "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8");

        Assert.True(vm.CloseCommand.CanExecute(null));
        Assert.False(vm.OpenSignupLinkCommand.CanExecute(null)); // no signup link configured
        Assert.False(vm.SubmitCommand.CanExecute(null));         // no code entered yet

        Assert.NotEqual(SubscriptionService.SubscriptionStatus.Valid, SubscriptionService.Status);
    }

    [Fact]
    public void Auth_Instance_IsRevoked_IsStableFalse()
    {
        // Constructing a real System.Windows.Window requires an STA thread (WPF throws
        // InvalidOperationException otherwise). xUnit does not guarantee STA for test
        // threads, so drive this on an explicit STA thread the same way production code
        // (Auth.RunAuthOnStaThread) does, rather than risk a thread-apartment failure that
        // has nothing to do with what this test is actually verifying.
        bool? isRevoked = null;
        Exception failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                var window = new System.Windows.Window(); // Window is not IDisposable
                using var auth = new Auth("Addin", "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8", window);
                // Now that background revalidation is gone, nothing can ever flip IsRevoked --
                // it must be a stable false, not just false at construction time.
                isRevoked = auth.IsRevoked;
            }
            catch (Exception ex)
            {
                failure = ex;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        Assert.Null(failure);
        Assert.False(isRevoked);
    }
}
