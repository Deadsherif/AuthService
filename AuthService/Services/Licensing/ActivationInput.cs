using System;

namespace AuthService.Services.Licensing
{
    public enum ActivationInputKind { Code, Token, TokenFile }

    public static class ActivationInput
    {
        public static ActivationInputKind Classify(string raw)
        {
            var s = (raw ?? string.Empty).Trim();
            if (s.EndsWith(".FO", StringComparison.OrdinalIgnoreCase))
                return ActivationInputKind.TokenFile;
            if (s.StartsWith("eyJ", StringComparison.Ordinal) && CountDots(s) == 2)
                return ActivationInputKind.Token;
            return ActivationInputKind.Code;
        }

        private static int CountDots(string s)
        {
            int n = 0;
            foreach (var c in s) if (c == '.') n++;
            return n;
        }
    }
}
