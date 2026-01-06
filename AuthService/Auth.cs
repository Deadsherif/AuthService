using AuthService.MVVM.View;
using AuthService.Services;
using System;
using System.Threading.Tasks;
using System.Windows;
using static AuthService.Services.SubscriptionService;

namespace AuthService
{

    public class Auth 
    {
        public static ApiResponseGet GetResponse { get; set; }
        public static bool IsGetResponseNull { get; set; } = true;
        public static int Tried { get; set; } = 0;
        public static async Task<SubscriptionService.SubscriptionStatus> ValidateAuth(string addinName, string addinID)
        {
            var model = LocalAuthCache.TryGetValidEntry(addinName, addinID);
            var IsValid = await model;
            if (IsValid)
            {
                SubscriptionService.Status = SubscriptionService.SubscriptionStatus.Valid;
                return SubscriptionStatus.Valid;
            }
            SubscriptionService.Status = SubscriptionService.SubscriptionStatus.NotFound;
            AuthWindow window = new AuthWindow(addinName, addinID);
            window.ShowDialog();
            return SubscriptionService.Status;

        }
    }
}
