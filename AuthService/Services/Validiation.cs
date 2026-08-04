using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Services
{
    public static class Validiation
    {
        public enum ValidiationType
        {
            FirstOption,
            Autodesk,
            None
        }

        public static ValidiationType GetValidiationType(string name)
        {
            const string keyPath = @"SOFTWARE\FirstOption";

            using var keys = Registry.LocalMachine.OpenSubKey(keyPath);
            if (keys == null)
                return ValidiationType.None;
            try
            {
                var value = (ValidiationType)keys.GetValue(name);
                if (value == ValidiationType.FirstOption)
                    return ValidiationType.FirstOption;
                if (value == ValidiationType.Autodesk)
                    return ValidiationType.Autodesk;
            }
            catch
            {
                return ValidiationType.None;
            }
            return ValidiationType.None;
        }
    }
}
