using AuthService.MVVM.View;
using AuthService.Services;
using AuthService.Services.Licensing;
using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using static AuthService.Services.SubscriptionService;


namespace AuthService
{

    public class Auth : IDisposable
    {
        private readonly string _addinName;
        private readonly string _addinID;
        public static ApiResponseGet GetResponse { get; set; }
        public static bool IsGetResponseNull { get; set; } = true;
        public static int Tried { get; set; } = 0;

        // Retired: background revalidation no longer runs (Task 15 full-token cutover), so this
        // event is never fired. Kept declared, never raised, solely so external add-ins that
        // still subscribe to it at compile time do not break. Do not wire anything to fire it
        // without re-introducing an actual background revalidation path.
        public static event EventHandler<BackgroundValidationFailedEventArgs> BackgroundValidationFailed;

        // Injectable seams for testing: production defaults construct a real gate over the
        // on-disk license store, the real wall clock, and the real machine-GUID device id.
        internal static Func<string, LicenseGate> GateFactory = addinId => new LicenseGate(LicenseStore.Default());
        internal static Func<DateTimeOffset> NowProvider = () => DateTimeOffset.UtcNow;
        internal static Func<string> DeviceProvider = DeviceFingerprint.CurrentDeviceId;

        // Best-effort trusted-online-time reading used to anchor the anti-rollback ratchet forward.
        // Must never throw and never block longer than DateHelper's own short timeout; returns null
        // on any failure so callers fall back to the local clock.
        internal static Func<DateTimeOffset?> OnlineTimeProvider = () =>
        {
            try
            {
                // Run on the thread pool so this never captures/blocks the caller's
                // SynchronizationContext (e.g. a UI thread in a CAD/Office host). Without
                // Task.Run, GetAwaiter().GetResult() here would block that context while
                // DateHelper's internal awaits try to resume back onto it -> deadlock.
                DateTime onlineDate = Task.Run(() => DateHelper.GetCurrentDateFromWebAsync()).GetAwaiter().GetResult();
                return new DateTimeOffset(DateTime.SpecifyKind(onlineDate, DateTimeKind.Utc));
            }
            catch
            {
                return null;
            }
        };

        public Auth(string addinName, string addinID)
            : this(addinName, addinID, new Window())
        {
        }

        public Auth(string addinName, string addinID, Window window)
        {
            _addinName = addinName;
            _addinID = addinID;
        }

        public Auth(string addinName, string addinID, Form window)
        {
            _addinName = addinName;
            _addinID = addinID;
        }

        // Background revalidation (and the subscription that watched for its failure) was
        // removed in the Task 15 cutover, so there is no longer any signal that can revoke a
        // session after the initial gate check. Always false; kept for public-surface stability.
        public bool IsRevoked => false;

        public string SignupLink { get; set; }

        public Task<SubscriptionService.SubscriptionStatus> Validate()
        {
            return ValidateAuth(_addinName, _addinID, SignupLink);
        }

        public void Dispose()
        {
        }

        public static async Task<SubscriptionService.SubscriptionStatus> ValidateAuth(string addinName, string addinID, string signupLink = null)
        {
            var gate = GateFactory(addinID);
            var status = gate.Evaluate(addinID, DeviceProvider(), NowProvider(), OnlineTimeProvider());
            if (status == GateStatus.Valid)
            {
                SubscriptionService.SetStatus(SubscriptionService.SubscriptionStatus.Valid);
                return SubscriptionStatus.Valid;
            }

            return await RunAuthOnStaThread(addinName, addinID, signupLink).ConfigureAwait(false);
        }

        private static Task<SubscriptionService.SubscriptionStatus> RunAuthOnStaThread(string addinName, string addinID, string signupLink)
        {
            var completion = new TaskCompletionSource<SubscriptionService.SubscriptionStatus>();
            var authThread = new Thread(() =>
            {
                SynchronizationContext.SetSynchronizationContext(
                    new DispatcherSynchronizationContext(Dispatcher.CurrentDispatcher));

                var frame = new DispatcherFrame();
                ValidateAuthCore(addinName, addinID, showUiWhenInvalid: true, signupLink).ContinueWith(task =>
                {
                    if (task.IsFaulted)
                    {
                        completion.SetException(task.Exception.GetBaseException());
                    }
                    else if (task.IsCanceled)
                    {
                        completion.SetCanceled();
                    }
                    else
                    {
                        completion.SetResult(task.Result);
                    }

                    frame.Continue = false;
                }, TaskScheduler.FromCurrentSynchronizationContext());

                Dispatcher.PushFrame(frame);
            });

            authThread.SetApartmentState(ApartmentState.STA);
            authThread.Start();

            return completion.Task;
        }

        // On a non-Valid gate result, the only remaining route to Valid is the interactive
        // AuthWindow token-activation UI. The legacy LocalAuthCache is never consulted here —
        // it is a forgeable client-side cache and granting Valid from it would be a clean
        // offline bypass of the license gate (Task 15 cutover).
        private static Task<SubscriptionService.SubscriptionStatus> ValidateAuthCore(string addinName, string addinID, bool showUiWhenInvalid, string signupLink = null)
        {
            SubscriptionService.SetStatus(SubscriptionService.SubscriptionStatus.NotFound);
            if (!showUiWhenInvalid)
            {
                return Task.FromResult(SubscriptionStatus.NotFound);
            }

            AuthWindow window = new AuthWindow(addinName, addinID, signupLink);
            window.ShowDialog();
            return Task.FromResult(SubscriptionService.Status);
        }
    }

    public sealed class BackgroundValidationFailedEventArgs : EventArgs
    {
        public BackgroundValidationFailedEventArgs(
            string addinName,
            string addinId,
            SubscriptionStatus status,
            string message)
        {
            AddinName = addinName;
            AddinId = addinId;
            Status = status;
            Message = message;
        }

        public string AddinName { get; }
        public string AddinId { get; }
        public SubscriptionStatus Status { get; }
        public string Message { get; }
    }

}
