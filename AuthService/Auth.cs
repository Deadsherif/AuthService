using AuthService.MVVM.Models;
using AuthService.MVVM.View;
using AuthService.Services;
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
        private const string BackgroundValidationFailedMessage = "Internet connection is required or a valid license is needed. This add-in will be closed.";
        private readonly string _addinName;
        private readonly string _addinID;
        private readonly AuthBackgroundFailureSubscription _backgroundFailureSubscription;
        public static ApiResponseGet GetResponse { get; set; }
        public static bool IsGetResponseNull { get; set; } = true;
        public static int Tried { get; set; } = 0;
        public static event EventHandler<BackgroundValidationFailedEventArgs> BackgroundValidationFailed;

        public Auth(string addinName, string addinID)
            : this(addinName, addinID, new Window())
        {
        }

        public Auth(string addinName, string addinID, Window window)
        {
            _addinName = addinName;
            _addinID = addinID;
            _backgroundFailureSubscription = new AuthBackgroundFailureSubscription(addinID, window);
        }

        public Auth(string addinName, string addinID, Form window)
        {
            _addinName = addinName;
            _addinID = addinID;
            _backgroundFailureSubscription = new AuthBackgroundFailureSubscription(addinID, window);
        }

        public bool IsRevoked => _backgroundFailureSubscription.IsRevoked;

        public string SignupLink { get; set; }

        public Task<SubscriptionService.SubscriptionStatus> Validate()
        {
            return ValidateAuth(_addinName, _addinID, SignupLink);
        }

        public void Dispose()
        {
            _backgroundFailureSubscription.Dispose();
        }

        public static async Task<SubscriptionService.SubscriptionStatus> ValidateAuth(string addinName, string addinID, string signupLink = null)
        {
            if (HasCacheEntry(addinID))
            {
                SubscriptionService.Status = SubscriptionService.SubscriptionStatus.Valid;
                _ = Task.Run(() => StartBackgroundRevalidation(addinName, addinID));
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

        private static async Task StartBackgroundRevalidation(string addinName, string addinID)
        {
            var handler = BackgroundValidationFailed;
            bool isValid = await LocalAuthCache.TryGetValidEntry(addinName, addinID).ConfigureAwait(false);
            if (isValid)
            {
                return;
            }

            LocalAuthCache.RemoveEntry(addinID);
            
            if (handler == null)
            {
                return;
            }

            handler(
                null,
                new BackgroundValidationFailedEventArgs(addinName, addinID, SubscriptionStatus.NotFound, BackgroundValidationFailedMessage));
        }

        private static async Task<SubscriptionService.SubscriptionStatus> ValidateAuthCore(string addinName, string addinID, bool showUiWhenInvalid, string signupLink = null)
        {
            bool isValid = await ValidateCachedEntryAgainstServer(addinID).ConfigureAwait(false);
            if (isValid)
            {
                SubscriptionService.Status = SubscriptionService.SubscriptionStatus.Valid;
                return SubscriptionStatus.Valid;
            }

            SubscriptionService.Status = SubscriptionService.SubscriptionStatus.NotFound;
            if (!showUiWhenInvalid)
            {
                return SubscriptionStatus.NotFound;
            }

            AuthWindow window = new AuthWindow(addinName, addinID, signupLink);
            window.ShowDialog();
            return SubscriptionService.Status;
        }

        private static async Task<bool> ValidateCachedEntryAgainstServer(string addinID)
        {
            var cache = LocalAuthCache.ReadCache();
            if (cache == null)
            {
                return false;
            }

            if (!cache.Entries.TryGetValue(addinID, out var entry) || entry == null)
            {
                return false;
            }

            DateTime currentDate = await DateHelper.GetCurrentDateFromWebAsync().ConfigureAwait(false);
            return await LocalAuthCache.SilentAuth(entry, currentDate).ConfigureAwait(false);
        }

        private static bool HasCacheEntry(string addinID)
        {
            var cache = LocalAuthCache.ReadCache();
            if (cache == null)
            {
                return false;
            }

            return cache.Entries.ContainsKey(addinID);
        }

        public static async Task<SubscriptionService.SubscriptionStatus> ValidateEntitlement(string appId, string userId, string addinName, string addinID)
        {
            var model = LocalAuthCache.TryGetValidEntry(addinName, addinID);
            var IsValid = await model;
            if (IsValid)
            {
                SubscriptionService.Status = SubscriptionService.SubscriptionStatus.Valid;
                return SubscriptionStatus.Valid;
            }
            SubscriptionService subscriptionService = new SubscriptionService();
            var entitlementResult = await subscriptionService.GetEntitlementResponseAsync(appId, userId);
            if (entitlementResult != null )
            {
                if (entitlementResult.IsValid) 
                {
                    SubscriptionService.Status = SubscriptionService.SubscriptionStatus.Valid;
                    string currentMac = SubscriptionService.GetCurrentMacAddress();
                    var code = await subscriptionService.PostEntitlementToFirstOptionAsync(appId, userId, currentMac);
                    LocalAuthCache._code = code;
                    LocalAuthCache.WriteRecord(addinID);
                    return SubscriptionStatus.Valid;
                }
                else
                {
                    SubscriptionService.Status = SubscriptionService.SubscriptionStatus.NotFound;
                    return SubscriptionStatus.NotFound;
                }
            }
            return SubscriptionStatus.Error;
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
