using System.Windows;
using AuthService.MVVM.ViewModel;

namespace AuthService.MVVM.View
{
    /// <summary>
    /// Interaction logic for AuthWindow.xaml
    /// </summary>
    public partial class AuthWindow : Window
    {
        public AuthWindow(string addinName, string addinID, string signupLink = null)
        {
            InitializeComponent();
            var viewModel = new AuthViewModel(addinName, addinID, signupLink);
            DataContext = viewModel;
            Loaded += (_, _) => viewModel.OnFirstOptionPremiseAuth(this);
        }
    }
}

