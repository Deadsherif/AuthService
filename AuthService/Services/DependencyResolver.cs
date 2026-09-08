using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace AuthService.Services
{
    /// <summary>
    /// Resolves AuthService's bundled dependencies (System.Text.Json, the
    /// Microsoft.IdentityModel.* JWT stack, etc.) from the folder AuthService.dll
    /// lives in, regardless of the exact assembly version requested.
    ///
    /// Hosts such as Revit load add-ins as libraries and ignore the add-in's
    /// .config, so binding redirects never apply. When a JWT library asks for an
    /// exact version of System.Text.Json that differs from the one shipped, the
    /// CLR throws FileNotFoundException. This handler makes any nearby matching
    /// assembly satisfy the request, so consumers get the fix for free just by
    /// referencing AuthService — no per-add-in wiring.
    /// </summary>
    [System.Reflection.Obfuscation(Feature = "renaming", Exclude = true, ApplyToMembers = true)]
    internal static class DependencyResolver
    {
        private static int _registered;

        [ModuleInitializer]
        internal static void Init()
        {
            // Runs the first time any AuthService member is touched, before
            // LicenseTokenVerifier (or anything else here) executes.
            if (System.Threading.Interlocked.Exchange(ref _registered, 1) != 0)
                return;

            AppDomain.CurrentDomain.AssemblyResolve += Resolve;
        }

        private static Assembly Resolve(object sender, ResolveEventArgs args)
        {
            string name = new AssemblyName(args.Name).Name;

            // Let the runtime handle satellite/resource assemblies normally.
            if (name.EndsWith(".resources", StringComparison.OrdinalIgnoreCase))
                return null;

            // Reuse an already-loaded assembly of the same simple name if present.
            foreach (Assembly loaded in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (string.Equals(loaded.GetName().Name, name, StringComparison.OrdinalIgnoreCase))
                    return loaded;
            }

            string dir = Path.GetDirectoryName(typeof(DependencyResolver).Assembly.Location);
            if (string.IsNullOrEmpty(dir))
                return null;

            string candidate = Path.Combine(dir, name + ".dll");
            return File.Exists(candidate) ? Assembly.LoadFrom(candidate) : null;
        }
    }
}

#if NETFRAMEWORK
namespace System.Runtime.CompilerServices
{
    // ModuleInitializerAttribute ships only in .NET 5+. Declaring it here lets the
    // C# compiler recognize [ModuleInitializer] on net47/net48 — the compiler binds
    // by full type name, not by which assembly defines it.
    [AttributeUsage(AttributeTargets.Method, Inherited = false)]
    internal sealed class ModuleInitializerAttribute : Attribute { }
}
#endif
