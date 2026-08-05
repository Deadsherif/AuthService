using System;
using AuthService.Services.Licensing;
using Xunit;

public class RollbackRatchetTests
{
    [Fact]
    public void DetectsBackwardClock()
    {
        var r = new RollbackRatchet { MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_750_000_000) };
        Assert.True(r.IsRollback(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000)));
        Assert.False(r.IsRollback(DateTimeOffset.FromUnixTimeSeconds(1_760_000_000)));
    }

    [Fact]
    public void AdvanceOnlyMovesForward()
    {
        var r = new RollbackRatchet { MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_750_000_000) };
        Assert.Equal(1_750_000_000, r.Advance(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000)).MaxDateSeen.ToUnixTimeSeconds());
        Assert.Equal(1_760_000_000, r.Advance(DateTimeOffset.FromUnixTimeSeconds(1_760_000_000)).MaxDateSeen.ToUnixTimeSeconds());
    }
}
