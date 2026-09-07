using AuthService.MVVM.View;
using AuthService.Services;
using AuthService.Services.Licensing;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using static AuthService.Services.SubscriptionService;


namespace AuthService
{

    public class Auth : IDisposable
    {
        private const string BackgroundValidationFailedMessage =
            "The server date contradicts the stored license timeline or shows that the license has expired. " +
            "This add-in has been revoked.";
        private static readonly ConcurrentDictionary<string, Task> BackgroundChecks =
            new ConcurrentDictionary<string, Task>(StringComparer.OrdinalIgnoreCase);

        private readonly string _addinName;
        private readonly string _addinID;
        private int _isRevoked;
        private int _disposed;
        public static ApiResponseGet GetResponse { get; set; }
        public static bool IsGetResponseNull { get; set; } = true;
        public static int Tried { get; set; } = 0;

        public static event EventHandler<BackgroundValidationFailedEventArgs> BackgroundValidationFailed;

        // Injectable seams for testing: production defaults construct a real gate over the
        // on-disk license store, the real wall clock, and the real machine-GUID device id.
        internal static Func<string, LicenseGate> GateFactory =
            addinId => new LicenseGate(LicenseStore.Default(addinId));
        internal static Func<DateTimeOffset> NowProvider = () => DateTimeOffset.UtcNow;
        internal static Func<string> DeviceProvider = DeviceFingerprint.CurrentDeviceId;
        internal static Func<Task<DateTimeOffset?>> OnlineTimeProvider = async () =>
        {
            var onlineDate = await DateHelper.TryGetCurrentDateFromWebAsync().ConfigureAwait(false);
            return onlineDate.HasValue
                ? new DateTimeOffset(DateTime.SpecifyKind(onlineDate.Value, DateTimeKind.Utc))
                : (DateTimeOffset?)null;
        };
        internal static TimeSpan BackgroundCheckDelay = TimeSpan.FromSeconds(2);

        public Auth(string addinName, string addinID)
            : this(addinName, addinID, new Window())
        {
        }

        public Auth(string addinName, string addinID, Window window)
        {
            _addinName = addinName;
            _addinID = addinID;
            BackgroundValidationFailed += OnBackgroundValidationFailed;
        }

        public Auth(string addinName, string addinID, Form window)
        {
            _addinName = addinName;
            _addinID = addinID;
            BackgroundValidationFailed += OnBackgroundValidationFailed;
        }

        public bool IsRevoked => Interlocked.CompareExchange(ref _isRevoked, 0, 0) == 1;

        public string SignupLink { get; set; }

        public Task<SubscriptionService.SubscriptionStatus> Validate()
        {
            return ValidateAuth(_addinName, _addinID, SignupLink);
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
                BackgroundValidationFailed -= OnBackgroundValidationFailed;
        }

        public static async Task<SubscriptionService.SubscriptionStatus> ValidateAuth(string addinName, string addinID, string signupLink = null)
        {
            var gate = GateFactory(addinID);
            var status = gate.Evaluate(addinID, DeviceProvider(), NowProvider());
            if (status == GateStatus.Valid)
            {
                SubscriptionService.SetStatus(SubscriptionService.SubscriptionStatus.Valid);
                StartBackgroundTimeValidation(addinName, addinID);
                return SubscriptionStatus.Valid;
            }

            return await RunAuthOnStaThread(addinName, addinID, signupLink).ConfigureAwait(false);
        }

        private static void StartBackgroundTimeValidation(string addinName, string addinID)
        {
            var check = BackgroundChecks.GetOrAdd(addinID, _ => Task.Run(async () =>
            {
                await Task.Delay(BackgroundCheckDelay).ConfigureAwait(false);
                var onlineTime = await OnlineTimeProvider().ConfigureAwait(false);
                if (!onlineTime.HasValue) return;

                var gate = GateFactory(addinID);
                var status = gate.Evaluate(
                    addinID,
                    DeviceProvider(),
                    NowProvider(),
                    onlineTime.Value);

                if (status == GateStatus.Valid) return;

                gate.Revoke();
                SubscriptionService.SetStatus(SubscriptionStatus.NotFound);
                BackgroundValidationFailed?.Invoke(
                    null,
                    new BackgroundValidationFailedEventArgs(
                        addinName,
                        addinID,
                        SubscriptionStatus.NotFound,
                        BackgroundValidationFailedMessage));
            }));

            check.ContinueWith(completed =>
            {
                BackgroundChecks.TryRemove(addinID, out _);
                if (completed.IsFaulted)
                    Trace.Fail("Background license validation failed", completed.Exception.ToString());
            }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }

        internal static Task GetBackgroundCheck(string addinID)
        {
            return BackgroundChecks.TryGetValue(addinID, out var check)
                ? check
                : Task.CompletedTask;
        }

        private void OnBackgroundValidationFailed(object sender, BackgroundValidationFailedEventArgs args)
        {
            if (string.Equals(args.AddinId, _addinID, StringComparison.OrdinalIgnoreCase))
                Interlocked.Exchange(ref _isRevoked, 1);
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
