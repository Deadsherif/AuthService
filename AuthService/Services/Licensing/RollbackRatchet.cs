using System;

namespace AuthService.Services.Licensing
{
    public sealed class RollbackRatchet
    {
        public DateTimeOffset MaxDateSeen { get; set; }
        public bool IsRollback(DateTimeOffset now) => now < MaxDateSeen;
        public RollbackRatchet Advance(DateTimeOffset now) =>
            new RollbackRatchet { MaxDateSeen = now > MaxDateSeen ? now : MaxDateSeen };
    }
}
