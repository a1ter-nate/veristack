using FsCheck;
using FsCheck.Xunit;
using OrderLifecycle.Domain;
using Xunit;

namespace OrderLifecycle.Tests;

public sealed class OrderPropertyTests
{
    [Property(MaxTest = 200)]
    public Property Pricing_IsBoundedMonotonicAndExactAtExtremes(NonNegativeInt unitPrice, NonNegativeInt qty, int rawDiscount)
    {
        var price = unitPrice.Get % 10_000;
        var count = qty.Get % 500;
        var discount = Math.Abs(rawDiscount % 101);

        var total = OrderStateMachine.CalculateTotalCents(price, count, discount);
        var gross = price * count;
        var fullDiscount = OrderStateMachine.CalculateTotalCents(price, count, 100);
        var zeroDiscount = OrderStateMachine.CalculateTotalCents(price, count, 0);

        return (total >= 0 && total <= gross && fullDiscount == 0 && zeroDiscount == gross).ToProperty();
    }

    [Fact]
    public void Pricing_RejectsInvalidArguments()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => OrderStateMachine.CalculateTotalCents(-1, 1, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => OrderStateMachine.CalculateTotalCents(100, -1, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => OrderStateMachine.CalculateTotalCents(100, 1, -1));
        Assert.Throws<ArgumentOutOfRangeException>(() => OrderStateMachine.CalculateTotalCents(100, 1, 101));
    }
}
