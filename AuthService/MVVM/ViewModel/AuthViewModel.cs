using AuthService.Commands;
using AuthService.MVVM.Models;
using AuthService.Services;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace AuthService.MVVM.ViewModel
{
    public class AuthViewModel : ViewModelBase
    {
        public static ApiResponseGet GetResponse { get; set; }
        public static bool IsGetResponseNull { get; set; } = true;
        public static int GetTried { get; set; } = 0;

        public static ApiResponsePost PostResponse { get; set; }
        public static bool IsPostResponseNull { get; set; } = true;
        public static int PostTried { get; set; } = 0;

        private readonly AuthApiClient _authApiClient = new AuthApiClient();
        public string _code;
        private string _serverResponse;
        private DateTime _endDate;
        private string _status;
        private System.Windows.Media.Brush _statusForeground;
        private bool _isLoading;
        private bool _isTrial;
        private string _closeButtonText;
        private string _signupLink;
        private readonly SubscriptionService _subscriptionService;
        private readonly string _guid;
        private bool _premiseAuthStarted;
        public string Code
        {
            get => _code;
            set
            {
                if (SetProperty(ref _code, value))
                {
                    ((RelayCommand)SubmitCommand).RaiseCanExecuteChanged();
                }
            }
        }

        public string ServerResponse
        {
            get => _serverResponse;
            set => SetProperty(ref _serverResponse, value);
        }

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
                {
                    ((RelayCommand)SubmitCommand).RaiseCanExecuteChanged();
                }
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

        public ICommand SubmitCommand { get; }
        public ICommand CloseCommand { get; }
        public ICommand OpenSignupLinkCommand { get; }

        public AuthViewModel(string Name, string ID, string signupLink = null)
        {
            _subscriptionService = new SubscriptionService();
            _guid = ID;
            _signupLink = signupLink;
            SubmitCommand = new RelayCommand(ExecuteSubmit, CanExecuteSubmit);
            CloseCommand = new RelayCommand(ExecuteClose, CanExecuteClose);
            OpenSignupLinkCommand = new RelayCommand(ExecuteOpenSignupLink, CanExecuteOpenSignupLink);
            StatusForeground = System.Windows.Media.Brushes.Black;
            CloseButtonText = "Close";
        }

        private async void ExecuteSubmit(object parameter)
        {
            if (string.IsNullOrWhiteSpace(Code))
                return;     

            IsLoading = true;
            ServerResponse = "Processing...";

            try
            {

                ApiResponseGet response = null;
                bool exist = false;
                bool validFromat = true;

                response = await _subscriptionService.GetRedemptionsAsync(Code);

                // Check if response is null (timeout or connection error)
                if (response == null)
                {
                    ServerResponse = string.Empty;
                    SubscriptionService.Status = SubscriptionService.SubscriptionStatus.Error;
                    Status = "Failed to connect or Code couldn't be found";
                    StatusForeground = System.Windows.Media.Brushes.Red;
                    CloseButtonText = "Close";
                    ((RelayCommand)CloseCommand).RaiseCanExecuteChanged();
                    return;
                }

                if (!response.Success)
                {
                    ServerResponse = string.Empty;
                    SubscriptionService.Status = SubscriptionService.SubscriptionStatus.NotFound;
                    Status = "Code not found";
                    StatusForeground = System.Windows.Media.Brushes.Red;
                    CloseButtonText = "Close";
                    ((RelayCommand)CloseCommand).RaiseCanExecuteChanged();
                    return;
                }
                // check if "data" field is populated and in the correct format
                GetResponse = response;
                IsGetResponseNull = false;
                GetTried = GetTried++;
                var redemptions = response.Payload.Redemptions.FirstOrDefault();
                bool dataExists = redemptions != null && redemptions.Data != null && redemptions.Data.Any();
                if (dataExists)
                {

                    // Validate that the addon_id from the response matches the ID passed to the view model
                    if (!string.IsNullOrEmpty(_guid))
                    {

                        string responseAddonGuid = response.Payload.addon.guid;
                        if (!string.Equals(_guid, responseAddonGuid, StringComparison.OrdinalIgnoreCase))
                        {
                            ServerResponse = string.Empty;
                            SubscriptionService.Status = SubscriptionService.SubscriptionStatus.Error;
                            Status = "Addon ID mismatch";
                            StatusForeground = System.Windows.Media.Brushes.Red;
                            CloseButtonText = "Close";
                            ((RelayCommand)CloseCommand).RaiseCanExecuteChanged();
                            return;
                        }
                    }
                    var subscription = response.Payload.Subscription;
                    if (!string.Equals(subscription.Status, "active", StringComparison.OrdinalIgnoreCase))
                    {
                        ServerResponse = string.Empty;
                        SubscriptionService.Status = SubscriptionService.SubscriptionStatus.Expired;
                        Status = $"Subscription is not active, Status: {subscription.Status}";
                        StatusForeground = System.Windows.Media.Brushes.Red;
                        CloseButtonText = "Close";
                        ((RelayCommand)CloseCommand).RaiseCanExecuteChanged();
                        return;
                    }

                    string dataStr = redemptions.Data.First();
                    if (!string.IsNullOrEmpty(dataStr))
                    {
                        var parts = dataStr.Split(',');
                        var validMacs = new List<string>();

                        // Regex to validate MAC address (XX:XX:XX:XX:XX:XX)
                        var macRegex = new Regex(@"^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$");

                        foreach (var part in parts)
                        {
                            var trimmed = part.Trim();
                            if (!macRegex.IsMatch(trimmed))
                            {
                                validFromat = false;
                                break;
                            }
                            validMacs.Add(trimmed);
                        }

                        if (validFromat)
                        {
                            var currentMac = SubscriptionService.GetCurrentMacAddress();
                            exist = validMacs.IndexOf(currentMac) >= 0 ;
                        }
                    }
                }
                if (!dataExists || !validFromat)
                {
                    var macs = SubscriptionService.GetAllMacAdressesFromPc();
                    var allMacs = string.Join(",", macs);
                    ApiResponsePost postResponse = await _subscriptionService.PostRedeemAsync(Code, allMacs);
                    exist = postResponse != null && postResponse.Success;
                    if (exist)
                    {
                        PostResponse = postResponse; IsPostResponseNull = false; PostTried = PostTried++;
                    }
                        
                }

                if (!exist)
                {
                    ServerResponse = string.Empty;
                    SubscriptionService.Status = SubscriptionService.SubscriptionStatus.Error;
                    Status = "Device not authorized";
                    StatusForeground = System.Windows.Media.Brushes.Red;
                    CloseButtonText = "Close";
                    ((RelayCommand)CloseCommand).RaiseCanExecuteChanged();
                    return;
                }

                ServerResponse = string.Empty; // Clear processing message
                
                if (response.Success && response.Payload?.Subscription != null)
                {
                    var subscription = response.Payload.Subscription;
                   
                    
                    EndDate = subscription.EndDate;
                    if (EndDate == DateTime.MinValue)
                        EndDate = DateTime.MaxValue;
                    _isTrial = subscription.IsTrial;
                    
                    DateTime currentDate = await DateHelper.GetCurrentDateFromWebAsync();
                    bool isExpired = EndDate < currentDate;
                    
                    if (isExpired)
                    {
                        SubscriptionService.Status = SubscriptionService.SubscriptionStatus.Expired;
                        StatusForeground = System.Windows.Media.Brushes.Red;
                        CloseButtonText = "Close";
                    }
                    else
                    {
                        SubscriptionService.Status = SubscriptionService.SubscriptionStatus.Valid;
                        StatusForeground = System.Windows.Media.Brushes.Green;
                        CloseButtonText = "Continue";
                        LocalAuthCache._code = Code;
                        LocalAuthCache.WriteRecord(_guid);
                    }
                    
                    string trialText = _isTrial ? "Trial" : "Subscriped";
                    string validityText = isExpired ? "Expired" : "Valid";
                    string endDateText = EndDate.ToString("yyyy/MM/dd");
                    
                    Status = $"{trialText} - {validityText} - {endDateText}";
                }
                else
                {
                    SubscriptionService.Status = SubscriptionService.SubscriptionStatus.NotFound;
                    Status = string.Empty;
                    StatusForeground = System.Windows.Media.Brushes.Black;
                    CloseButtonText = "Close";
                }
                
                ((RelayCommand)CloseCommand).RaiseCanExecuteChanged();
            }
            finally
            {
                IsLoading = false;
            }
        }

        internal async void OnFirstOptionPremiseAuth(Window window)
        {
            if (_premiseAuthStarted || window == null)
            {
                return;
            }

            _premiseAuthStarted = true;
            IsLoading = false;

            var authentication = await _authApiClient
                .AuthenticateAsync(
                    FirstOptionPremiseAuth.CompanyName,
                    FirstOptionPremiseAuth.ServiceUserName,
                    FirstOptionPremiseAuth.ServicePassword)
                .ConfigureAwait(true);

            if (!authentication.Authenticated)
            {
                ServerResponse = string.Empty;
                IsLoading = false;
                return;
            }

            SubscriptionService.Status = SubscriptionService.SubscriptionStatus.Valid;
            EndDate = DateTime.MaxValue;
            Status = "On Premise - Valid";
            StatusForeground = System.Windows.Media.Brushes.Green;
            CloseButtonText = "Continue";
            ServerResponse = string.Empty;

            LocalAuthCache._code = LocalAuthCache.PremiseCacheCode;
            LocalAuthCache.WriteRecordMax(_guid);

            ((RelayCommand)CloseCommand).RaiseCanExecuteChanged();
            IsLoading = false;

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

        private bool CanExecuteSubmit(object parameter)
        {
            return !string.IsNullOrWhiteSpace(Code) && !IsLoading;
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
