using System.IO;
using Xunit;

public class NoHardcodedSecretsTests
{
    [Theory]
    [InlineData("AuthService/Services/FirstOptionPremiseAuth.cs", "\"admin\"")]
    [InlineData("AuthService/Services/ApiEndpoints.cs", "4c69b7fa5010519e87f2aa6e7b6b5a16")]
    public void SourceDoesNotContainSecret(string relativePath, string secret)
    {
        var root = Path.GetFullPath(Path.Combine(System.AppContext.BaseDirectory, "..", "..", "..", ".."));
        var text = File.ReadAllText(Path.Combine(root, relativePath));
        Assert.DoesNotContain(secret, text);
    }
}
