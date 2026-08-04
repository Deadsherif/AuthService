using System;
using System.Threading;
using System.Windows;

namespace AuthService
{
    internal sealed class AuthBackgroundFailureSubscription : IDisposable
    {
        private readonly string _addinId;
        private Object _window;
        private int _authRevoked;
        private int _messageShown;
        private int _disposed;

        public AuthBackgroundFailureSubscription(string addinId, Window window)
        {
            _addinId = addinId;
            AttachWindow(window);
            Auth.BackgroundValidationFailed += OnBackgroundValidationFailed;
        }

        public AuthBackgroundFailureSubscription(string addinId, Form window)
        {
            _addinId = addinId;
            AttachWindow(window);
            Auth.BackgroundValidationFailed += OnBackgroundValidationFailed;
        }

        public bool IsRevoked => Interlocked.CompareExchange(ref _authRevoked, 0, 0) == 1;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 1)
            {
                return;
            }

            Auth.BackgroundValidationFailed -= OnBackgroundValidationFailed;

            Object objectWindow = null;

            Form form = _window as Form;
            Window window = _window as Window;

            if (objectWindow != null)
            {
                if (objectWindow is Form)
                {
                    form.Closed -= OnWindowClosed;
                }
                else if (objectWindow is Window)
                {
                    window.Closed -= OnWindowClosed;
                }
            }
        }

        private void AttachWindow(Window window)
        {
            
            if (window != null)
            {
                window.Closed += OnWindowClosed;
                _window = window;
            }
        }

        private void AttachWindow(Form window)
        {
            
            if (window != null)
            {
                window.Closed += OnWindowClosed;
                _window = window;
            }
        }

        private void OnWindowClosed(object sender, EventArgs args)
        {
            Dispose();
        }

        private void OnBackgroundValidationFailed(object sender, BackgroundValidationFailedEventArgs args)
        {
            if (!string.Equals(args.AddinId, _addinId, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            Interlocked.Exchange(ref _authRevoked, 1);
            CloseWindowAndShowMessage(args.Message);
        }

        private void CloseWindowAndShowMessage(string message)
        {
            var window = _window as Window;
            if (window == null)
            {
                CloseFormAndShowMessage(message);
                return;
            }
            if (window != null)
            {
                window.Dispatcher.BeginInvoke(new Action(() =>
                {
                    ShowMessageOnce(message);
                    if (window.IsVisible)
                    {
                        window.Close();
                    }
                }));
                return;
            }

            var dispatcher = System.Windows.Application.Current?.Dispatcher;
            if (dispatcher == null)
            {
                ShowMessageOnce(message);
                return;
            }

            dispatcher.BeginInvoke(new Action(() => ShowMessageOnce(message)));
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "<Pending>")]
        private void CloseFormAndShowMessage(string message)
        {
            var window = _window as Form;
            if (window == null)
            {
                return;
            }
            if (window != null)
            {
                window.BeginInvoke(new Action(() =>
                {
                    ShowMessageOnce(message);
                    if (window.Visible)
                    {
                        window.Close();
                    }
                }));
                return;
            }

            var dispatcher = System.Windows.Application.Current?.Dispatcher;
            if (dispatcher == null)
            {
                ShowMessageOnce(message);
                return;
            }

            dispatcher.BeginInvoke(new Action(() => ShowMessageOnce(message)));
        }

        private void ShowMessageOnce(string message)
        {
            if (Interlocked.Exchange(ref _messageShown, 1) == 0)
            {
                System.Windows.MessageBox.Show(message, "Subscription Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
    }
}
