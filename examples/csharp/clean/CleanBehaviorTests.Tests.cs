using Veristack.Examples.Clean;
using Xunit;

namespace Veristack.Examples.Clean;

public sealed class CleanBehaviorTests
{
    [Theory]
    [InlineData(2500, "AUTH-1", "Captured AUTH-1")]
    public void DescribesCapturedPaymentDeterministically(int cents, string auth, string expected)
    {
        var state = new PaymentState.Captured(cents, auth);
        Assert.Equal(expected, PaymentFormatter.Describe(state));
    }
}
