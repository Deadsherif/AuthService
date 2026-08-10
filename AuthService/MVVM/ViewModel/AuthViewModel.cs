using AuthService.Commands;
using AuthService.Services;
using AuthService.Services.Licensing;
using System;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace AuthService.MVVM.ViewModel
{
    public class AuthViewModel : ViewModelBase
    {
        // Static cache slot consulted by DateHelper.GetCurrentDateFromWebAsync as a
        // reuse-first-response optimization. Nothing in AuthViewModel writes to these
        // anymore now that the short-code redemption flow is gone (see Task 16); they
        // stay at their default (null/true) forever, so DateHelper always falls through
        // to its own fresh redemption call. Kept here (rather than deleted) solely
        // because DateHelper.cs depends on this exact static surface.
        public static ApiResponseGet GetResponse { get; set; }
        public static bool IsGetResponseNull { get; set; } = true;

        private DateTime _endDate;
        private string _status;
        private System.Windows.Media.Brush _statusForeground;
        private bool _isLoading;
        private string _closeButtonText;
        private string _signupLink;
        private readonly string _guid;

        public DateTime EndDate
        {
            get => _endDate;
            set => SetProperty(ref _endDate, value);
        }

        public string Status
        {
            get => _status;
            set => SetProperty(ref _status, value);
        }

        public System.Windows.Media.Brush StatusForeground
        {
            get => _statusForeground;
            set => SetProperty(ref _statusForeground, value);
        }

        public bool IsLoading
        {
            get => _isLoading;
            set
            {
                if (SetProperty(ref _isLoading, value))
                    (SubmitCommand as RelayCommand)?.RaiseCanExecuteChanged();
            }
        }

        public string CloseButtonText
        {
            get => _closeButtonText;
            set => SetProperty(ref _closeButtonText, value);
        }

        public string SignupLink
        {
            get => _signupLink;
            set
            {
                if (SetProperty(ref _signupLink, value))
                {
                    OnPropertyChanged(nameof(SignupLinkVisibility));
                    ((RelayCommand)OpenSignupLinkCommand).RaiseCanExecuteChanged();
                }
            }
        }

        public Visibility SignupLinkVisibility =>
            string.IsNullOrWhiteSpace(SignupLink) ? Visibility.Collapsed : Visibility.Visible;

        public ICommand CloseCommand { get; }
        public ICommand OpenSignupLinkCommand { get; }

        // Test seams: production defaults are seeded in the constructor, and unit tests
        // overwrite them before calling ActivateAsync. Kept as plain (non-nullable)
        // types per the task spec so tests can assign them directly.
        public LicenseStore TokenStoreOverride { get; set; }
        public DateTimeOffset NowOverride { get; set; }
        public string DeviceOverride { get; set; }
        public IMintClient MintClientOverride { get; set; }
        public ILegacyActivationClient LegacyClientOverride { get; set; }
        public bool UseLegacyActivation { get; set; }

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

        public AuthViewModel(string Name, string ID, string signupLink = null)
        {
            _guid = ID;
            _signupLink = signupLink;
            CloseCommand = new RelayCommand(ExecuteClose, CanExecuteClose);
            OpenSignupLinkCommand = new RelayCommand(ExecuteOpenSignupLink, CanExecuteOpenSignupLink);
            SubmitCommand = new RelayCommand(ExecuteSubmit, CanExecuteSubmit);
            StatusForeground = System.Windows.Media.Brushes.Black;
            CloseButtonText = "Close";

            // Production defaults for the test seams above.
            TokenStoreOverride = null; // resolved lazily to LicenseStore.Default() at use time
            NowOverride = DateTimeOffset.UtcNow;
            DeviceOverride = DeviceFingerprint.CurrentDeviceId();
            MintClientOverride = new HttpMintClient(new System.Net.Http.HttpClient(), ActivationEndpoints.MintUrl);
            LegacyClientOverride = new HttpLegacyActivationClient(
                new System.Net.Http.HttpClient(),
                ActivationEndpoints.MarketplaceRedemptionsUrl,
                ActivationEndpoints.MarketplaceRedeemUrl);
            UseLegacyActivation = !ActivationEndpoints.MintConfigured;
        }

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
                    if (UseLegacyActivation)
                        await RegisterLegacyAsync(raw);
                    else
                        await ActivateWithCodeAsync(raw);
                    return;
            }
        }

        private async Task ActivateWithCodeAsync(string code)
        {
            IsLoading = true;
            ServerResponse = "Contacting activation server...";
            Status = string.Empty;
            StatusForeground = System.Windows.Media.Brushes.Black;
            try
            {
                var result = await MintClientOverride.RequestTokenAsync(code, DeviceFingerprint.Hash(DeviceOverride)).ConfigureAwait(true);
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
                    ServerResponse = "Registration is bending Approval you will receive an email soon";
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

        private void VerifyAndStore(string token)
        {
            var verifier = new LicenseTokenVerifier();
            var result = verifier.Verify(token, NowOverride);

            // Activation requires a currently-valid (unexpired, correctly-signed) token —
            // unlike the gate, which also accepts Expired to distinguish "was valid, now
            // expired" from "never valid". A token that is already expired should not be
            // accepted as a fresh activation.
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

            // iat floor: seed MaxDateSeen with the later of the token's issue date and
            // "now", so the anti-rollback ratchet in LicenseGate starts at (at least) the
            // token's own iat rather than just the activation moment.
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

        private void ExecuteClose(object parameter)
        {
            if (parameter is System.Windows.Window window)
            {
                window.Close();
            }
        }

        private void ExecuteOpenSignupLink(object parameter)
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = SignupLink,
                UseShellExecute = true
            });
        }

        private bool CanExecuteClose(object parameter)
        {
            return true; // Always enabled
        }

        private bool CanExecuteOpenSignupLink(object parameter)
        {
            return !string.IsNullOrWhiteSpace(SignupLink);
        }
    }
}
