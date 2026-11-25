using FsCheck;
using FsCheck.Experimental;
using OrderLifecycle.Domain;
using Xunit;

namespace OrderLifecycle.Tests;

public sealed class OrderRunner
{
    public OrderState Current { get; private set; } = new OrderState.Pending(2_500);

    public TransitionOutcome Apply(OrderEvent evt)
    {
        var outcome = OrderStateMachine.Transition(Current, evt);
        if (outcome is TransitionOutcome.Accepted accepted)
        {
            Current = accepted.NextState;
        }

        return outcome;
    }
}

public sealed record ModelState(string Phase);

internal sealed class ApplyOrderEventOp(OrderEvent evt) : Operation<OrderRunner, ModelState>
{
    public override ModelState Run(ModelState model) =>
        (model.Phase, evt) switch
        {
            ("pending", OrderEvent.Authorize a) when !string.IsNullOrWhiteSpace(a.AuthCode) => new ModelState("authorized"),
            ("pending", OrderEvent.Cancel c) when !string.IsNullOrWhiteSpace(c.Reason) => new ModelState("cancelled"),
            ("authorized", OrderEvent.Ship s) when !string.IsNullOrWhiteSpace(s.TrackingId) => new ModelState("shipped"),
            ("authorized", OrderEvent.Cancel c) when !string.IsNullOrWhiteSpace(c.Reason) => new ModelState("cancelled"),
            _ => model,
        };

    public override Property Check(OrderRunner sut, ModelState model)
    {
        var outcome = sut.Apply(evt);
        var actualPhase = OrderStateMachine.NameOf(sut.Current);
        var expectedPhase = model.Phase;
        var validOutcome = outcome is TransitionOutcome.Accepted or TransitionOutcome.Rejected;
        return (validOutcome && actualPhase == expectedPhase).ToProperty();
    }

    public override string ToString() => evt.ToString();
}

internal sealed class OrderSetup : Setup<OrderRunner, ModelState>
{
    public override OrderRunner Actual() => new();

    public override ModelState Model() => new("pending");
}

internal sealed class OrderLifecycleMachine : Machine<OrderRunner, ModelState>
{
    public override Arbitrary<Setup<OrderRunner, ModelState>> Setup =>
        Arb.From(Gen.Constant<Setup<OrderRunner, ModelState>>(new OrderSetup()));

    public override Gen<Operation<OrderRunner, ModelState>> Next(ModelState model) =>
        Gen.Elements<Operation<OrderRunner, ModelState>>(
            new ApplyOrderEventOp(new OrderEvent.Authorize("AUTH-OK")),
            new ApplyOrderEventOp(new OrderEvent.Authorize("")),
            new ApplyOrderEventOp(new OrderEvent.Ship("TRK-OK")),
            new ApplyOrderEventOp(new OrderEvent.Ship(" ")),
            new ApplyOrderEventOp(new OrderEvent.Cancel("customer")),
            new ApplyOrderEventOp(new OrderEvent.Cancel("")));
}

public sealed class OrderStateMachineMbtTests
{
    [Fact]
    public void StatefulModelBasedTest_HoldsAcrossRandomInterleavings()
    {
        var machine = new OrderLifecycleMachine();
        machine.ToProperty().QuickCheckThrowOnFailure();
    }
}
