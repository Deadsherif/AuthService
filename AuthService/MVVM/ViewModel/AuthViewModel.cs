using AuthService.Commands;
using AuthService.Services;
using AuthService.Services.Licensing;
using System;
using System.Diagnostics;
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
            set => SetProperty(ref _isLoading, value);
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
        public ICommand ActivateTokenCommand { get; }

        private string _pastedToken;

        // Test seams: production defaults are seeded in the constructor, and unit tests
        // overwrite them before calling ActivateTokenCommand. Kept as plain (non-nullable)
        // types per the task spec so tests can assign them directly.
        public LicenseStore TokenStoreOverride { get; set; }
        public DateTimeOffset NowOverride { get; set; }
        public string DeviceOverride { get; set; }

        public string PastedToken
        {
            get => _pastedToken;
            set
            {
                if (SetProperty(ref _pastedToken, value))
                {
                    ((RelayCommand)ActivateTokenCommand).RaiseCanExecuteChanged();
                }
            }
        }

        // Shown in the UI so an air-gapped user can mint a token elsewhere for this exact
        // device without needing network access to this machine.
        public string DeviceFingerprintDisplay
        {
            get
            {
                var hash = DeviceFingerprint.Hash(DeviceFingerprint.CurrentDeviceId());
                return hash.Length > 12 ? hash.Substring(0, 12) : hash;
            }
        }

        public AuthViewModel(string Name, string ID, string signupLink = null)
        {
            _guid = ID;
            _signupLink = signupLink;
            CloseCommand = new RelayCommand(ExecuteClose, CanExecuteClose);
            OpenSignupLinkCommand = new RelayCommand(ExecuteOpenSignupLink, CanExecuteOpenSignupLink);
            ActivateTokenCommand = new RelayCommand(ExecuteActivateToken, CanExecuteActivateToken);
            StatusForeground = System.Windows.Media.Brushes.Black;
            CloseButtonText = "Close";

            // Production defaults for the test seams above.
            TokenStoreOverride = null; // resolved lazily to LicenseStore.Default() at use time
            NowOverride = DateTimeOffset.UtcNow;
            DeviceOverride = DeviceFingerprint.CurrentDeviceId();
        }

        private bool CanExecuteActivateToken(object parameter)
        {
            return !string.IsNullOrWhiteSpace(PastedToken);
        }

        private void ExecuteActivateToken(object parameter)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(PastedToken))
                {
                    Status = "Paste a license token first";
                    StatusForeground = System.Windows.Media.Brushes.Red;
                    return;
                }

                var verifier = new LicenseTokenVerifier();
                var result = verifier.Verify(PastedToken, NowOverride);

                // Activation requires a currently-valid (unexpired, correctly-signed) token —
                // unlike the gate, which also accepts Expired to distinguish "was valid, now
                // expired" from "never valid". A pasted token that is already expired should
                // not be accepted as a fresh activation.
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
                store.Write(new StoredLicense { Token = PastedToken, MaxDateSeen = seededFloor });

                SubscriptionService.SetStatus(SubscriptionService.SubscriptionStatus.Valid);
                EndDate = claims.Expires.UtcDateTime;
                Status = "Activated - Valid";
                StatusForeground = System.Windows.Media.Brushes.Green;
                CloseButtonText = "Continue";
                ((RelayCommand)CloseCommand).RaiseCanExecuteChanged();
            }
            catch (Exception)
            {
                Status = "Activation error";
                StatusForeground = System.Windows.Media.Brushes.Red;
            }
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
