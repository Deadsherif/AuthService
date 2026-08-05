using System.Collections.Generic;
using AuthService.Services;
using Xunit;

public class MacListParsingTests
{
    [Fact]
    public void MalformedEntry_DoesNotTruncateList()
    {
        var valid = new List<string>();
        // "GARBAGE" is malformed but a real MAC follows it
        LocalAuthCache.IsMacValid(valid, "GARBAGE, AA:BB:CC:DD:EE:FF");
        Assert.Contains("AA:BB:CC:DD:EE:FF", valid);
    }
}
