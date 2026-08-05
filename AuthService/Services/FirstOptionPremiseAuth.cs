using System;

namespace AuthService.Services
{
    internal static class FirstOptionPremiseAuth
    {
        public const string CompanyName = "First Option";

        public static string ServiceUserName =>
            Environment.GetEnvironmentVariable("FIRSTOPTION_SVC_USER") ?? string.Empty;

        public static string ServicePassword =>
            Environment.GetEnvironmentVariable("FIRSTOPTION_SVC_PASS") ?? string.Empty;
    }
}
