using OrderLifecycle.Domain;
using Xunit;

namespace OrderLifecycle.Tests;

public sealed class OrderFormalProofTests
{
    private sealed record TrackedState(
        OrderState State,
        bool EverAuthorized,
        bool WasTerminal,
        bool TerminalMutated,
        int InitialAmount);

    private static readonly OrderEvent[] Alphabet =
    [
        new OrderEvent.Authorize("AUTH-1"),
        new OrderEvent.Authorize(string.Empty),
        new OrderEvent.Ship("TRK-1"),
        new OrderEvent.Ship(" "),
        new OrderEvent.Cancel("customer"),
        new OrderEvent.Cancel(string.Empty),
    ];

    [Fact]
    public void ExhaustiveStateSpaceModelCheckProvesAllSafetyAndReachabilityInvariants()
    {
        var initial = new TrackedState(
            new OrderState.Pending(1500),
            EverAuthorized: false,
            WasTerminal: false,
            TerminalMutated: false,
            InitialAmount: 1500);

        var visited = new HashSet<TrackedState> { initial };
        var queue = new Queue<TrackedState>();
        queue.Enqueue(initial);

        bool reachedShipped = false;
        bool reachedCancelled = false;

        while (queue.Count > 0)
        {
            var current = queue.Dequeue();

            Assert.False(current.TerminalMutated);

            switch (current.State)
            {
                case OrderState.Pending p:
                    Assert.Equal(current.InitialAmount, p.AmountCents);
                    break;
                case OrderState.Authorized a:
                    Assert.Equal(current.InitialAmount, a.AmountCents);
                    Assert.False(string.IsNullOrWhiteSpace(a.AuthCode));
                    break;
                case OrderState.Shipped s:
                    Assert.True(current.EverAuthorized);
                    Assert.Equal(current.InitialAmount, s.AmountCents);
                    Assert.False(string.IsNullOrWhiteSpace(s.AuthCode));
                    Assert.False(string.IsNullOrWhiteSpace(s.TrackingId));
                    reachedShipped = true;
                    break;
                case OrderState.Cancelled c:
                    Assert.False(string.IsNullOrWhiteSpace(c.Reason));
                    reachedCancelled = true;
                    break;
                default:
                    throw new InvalidOperationException($"Unexpected state: {current.State}");
            }

            foreach (var evt in Alphabet)
            {
                var outcome = OrderStateMachine.Transition(current.State, evt);
                var nextOrder = outcome switch
                {
                    TransitionOutcome.Accepted a => a.NextState,
                    TransitionOutcome.Rejected r => r.UnchangedState,
                    _ => throw new InvalidOperationException($"Unexpected outcome: {outcome}"),
                };

                bool nowAuthorized = nextOrder is OrderState.Authorized;
                bool nowTerminal = nextOrder is OrderState.Shipped or OrderState.Cancelled;
                bool mutatedAfterTerminal = current.WasTerminal && !Equals(nextOrder, current.State);

                var nextTracked = new TrackedState(
                    nextOrder,
                    current.EverAuthorized || nowAuthorized,
                    current.WasTerminal || nowTerminal,
                    current.TerminalMutated || mutatedAfterTerminal,
                    current.InitialAmount);

                if (visited.Add(nextTracked))
                {
                    queue.Enqueue(nextTracked);
                }
            }
        }

        Assert.True(reachedShipped);
        Assert.True(reachedCancelled);
        Assert.True(visited.Count >= 4);
    }
}
