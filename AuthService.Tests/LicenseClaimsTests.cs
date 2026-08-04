using System;
using System.Collections.Generic;
using AuthService.Services.Licensing;
using Xunit;

public class LicenseClaimsTests
{
    [Fact]
    public void FromJwtPayload_MapsAllClaims()
    {
        var payload = new Dictionary<string, object>
        {
            ["iss"] = "firstoption",
            ["addon"] = "9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8",
            ["tier"] = "paid",
            ["iat"] = 1_700_000_000L,
            ["exp"] = 1_800_000_000L,
            ["device"] = "abc123",
            ["jti"] = "tok-1"
        };

        var claims = LicenseClaims.FromJwtPayload(payload);

        Assert.Equal("firstoption", claims.Issuer);
        Assert.Equal("9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8", claims.AddonId);
        Assert.Equal("paid", claims.Tier);
        Assert.Equal(1_800_000_000L, claims.Expires.ToUnixTimeSeconds());
        Assert.Equal("abc123", claims.DeviceHash);
        Assert.Equal("tok-1", claims.TokenId);
    }
}
