using System;
using System.IO;
using System.Linq;
using Xunit;

public class NoHardcodedSecretsTests
{
    // Scans every shipped source file (all *.cs under AuthService/, recursively) rather than
    // a fixed list of file paths, so this test keeps working across file moves/deletions in
    // that cluster (e.g. the entitlement/premise/marketplace-client cleanup that removed
    // FirstOptionPremiseAuth.cs and ApiEndpoints.cs) without needing to be re-pointed.
    [Theory]
    [InlineData("\"admin\"")]
    [InlineData("4c69b7fa5010519e87f2aa6e7b6b5a16")]
    public void ShippedSourceDoesNotContainSecret(string secret)
    {
        var root = Path.GetFullPath(Path.Combine(System.AppContext.BaseDirectory, "..", "..", "..", ".."));
        var authServiceDir = Path.Combine(root, "AuthService");

        var sourceFiles = Directory.EnumerateFiles(authServiceDir, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                         .Any(part => part == "bin" || part == "obj"))
            .ToList();

        Assert.NotEmpty(sourceFiles);

        var allShippedSource = string.Join(
            Environment.NewLine,
            sourceFiles.Select(File.ReadAllText));

        Assert.DoesNotContain(secret, allShippedSource);
    }
}
