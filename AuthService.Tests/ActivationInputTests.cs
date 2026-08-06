using AuthService.Services.Licensing;
using Xunit;

public class ActivationInputTests
{
    [Theory]
    [InlineData(@"C:\Users\me\license.FO", ActivationInputKind.TokenFile)]
    [InlineData(@"C:\Users\me\LICENSE.fo", ActivationInputKind.TokenFile)]
    [InlineData("  D:\\path\\x.FO  ", ActivationInputKind.TokenFile)]
    [InlineData("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJmbyJ9.sig", ActivationInputKind.Token)]
    [InlineData("aWiS1Tbo2bm", ActivationInputKind.Code)]
    [InlineData("ABC-123", ActivationInputKind.Code)]
    public void Classify_ReturnsExpectedKind(string raw, ActivationInputKind expected)
    {
        Assert.Equal(expected, ActivationInput.Classify(raw));
    }
}
