using Veristack.Examples.Caught;
using Xunit;

namespace Veristack.Examples.Caught;

public sealed class BadTests
{
    [Fact(Skip = "flaky on CI")]
    public void SkippedTautology()
    {
        Assert.True(true);
    }

    [Fact]
    public void FlakyNonHermetic()
    {
        Environment.SetEnvironmentVariable("MODE", "test");
        var now = DateTime.UtcNow;
        Thread.Sleep(50);
        var bag = new PaymentBag { Status = now.Ticks > 0 ? "pending" : "captured" };
        Assert.Equal("Waiting", bag.Label());
    }
}
