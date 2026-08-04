using System;

namespace AuthService.Services
{
    public static class ApiEndpoints
    {
        internal const string BaseUrl = "http://192.168.1.12:3000";
        //internal const string BaseUrl = "http://localhost:3000";
        internal const string ApiKey = "4c69b7fa5010519e87f2aa6e7b6b5a16d17040f488a512f58c06bc5127357e85";
        internal const string Reports = "/api/reports";
        internal const string Users = "/api/users";
        internal const string AdminSnapshot = "/api/admin/snapshot";
        internal const string AdminWorkflows = "/api/admin/workflows";

        public static string Authenticate(string company, string userName, string password)
        {
            var encodedCompany = Uri.EscapeDataString(company ?? string.Empty);
            var encodedUserName = Uri.EscapeDataString(userName ?? string.Empty);
            var encodedPassword = Uri.EscapeDataString(password ?? string.Empty);
            return $"/api/users/authenticate?company={encodedCompany}&userName={encodedUserName}&password={encodedPassword}";
        }
    }

}
