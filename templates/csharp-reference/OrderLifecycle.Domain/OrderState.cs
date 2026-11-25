using System.Diagnostics;

namespace OrderLifecycle.Domain;

public abstract record OrderState
{
    private OrderState()
    {
    }

    public sealed record Pending(int AmountCents) : OrderState;

    public sealed record Authorized(int AmountCents, string AuthCode) : OrderState;

    public sealed record Shipped(int AmountCents, string AuthCode, string TrackingId) : OrderState;

    public sealed record Cancelled(string Reason) : OrderState;
}

public abstract record OrderEvent
{
    private OrderEvent()
    {
    }

    public sealed record Authorize(string AuthCode) : OrderEvent;

    public sealed record Ship(string TrackingId) : OrderEvent;

    public sealed record Cancel(string Reason) : OrderEvent;
}

public abstract record TransitionOutcome
{
    private TransitionOutcome()
    {
    }

    public sealed record Accepted(OrderState NextState) : TransitionOutcome;

    public sealed record Rejected(string Code, OrderState UnchangedState) : TransitionOutcome;
}

public static class OrderStateMachine
{
    public static TransitionOutcome Transition(OrderState state, OrderEvent evt) =>
        (state, evt) switch
        {
            (OrderState.Pending pending, OrderEvent.Authorize auth) when !string.IsNullOrWhiteSpace(auth.AuthCode) =>
                new TransitionOutcome.Accepted(new OrderState.Authorized(pending.AmountCents, auth.AuthCode)),
            (OrderState.Pending pending, OrderEvent.Authorize) =>
                new TransitionOutcome.Rejected("INVALID_AUTH_CODE", pending),
            (OrderState.Pending, OrderEvent.Cancel cancel) when !string.IsNullOrWhiteSpace(cancel.Reason) =>
                new TransitionOutcome.Accepted(new OrderState.Cancelled(cancel.Reason)),
            (OrderState.Pending pending, OrderEvent.Cancel) =>
                new TransitionOutcome.Rejected("INVALID_CANCEL_REASON", pending),
            (OrderState.Pending pending, OrderEvent.Ship) =>
                new TransitionOutcome.Rejected("CANNOT_SHIP_UNPAID", pending),

            (OrderState.Authorized auth, OrderEvent.Ship ship) when !string.IsNullOrWhiteSpace(ship.TrackingId) =>
                new TransitionOutcome.Accepted(new OrderState.Shipped(auth.AmountCents, auth.AuthCode, ship.TrackingId)),
            (OrderState.Authorized auth, OrderEvent.Ship) =>
                new TransitionOutcome.Rejected("INVALID_TRACKING_ID", auth),
            (OrderState.Authorized, OrderEvent.Cancel cancel) when !string.IsNullOrWhiteSpace(cancel.Reason) =>
                new TransitionOutcome.Accepted(new OrderState.Cancelled(cancel.Reason)),
            (OrderState.Authorized auth, OrderEvent.Cancel) =>
                new TransitionOutcome.Rejected("INVALID_CANCEL_REASON", auth),
            (OrderState.Authorized auth, OrderEvent.Authorize) =>
                new TransitionOutcome.Rejected("ALREADY_AUTHORIZED", auth),

            (OrderState.Shipped shipped, _) =>
                new TransitionOutcome.Rejected("TERMINAL_SHIPPED", shipped),
            (OrderState.Cancelled cancelled, _) =>
                new TransitionOutcome.Rejected("TERMINAL_CANCELLED", cancelled),

            _ => throw new UnreachableException($"Unhandled state/event pair: {state} / {evt}"),
        };

    public static string NameOf(OrderState state) =>
        state switch
        {
            OrderState.Pending => "pending",
            OrderState.Authorized => "authorized",
            OrderState.Shipped => "shipped",
            OrderState.Cancelled => "cancelled",
            _ => throw new UnreachableException($"Unhandled state: {state}"),
        };

    public static int CalculateTotalCents(int unitPriceCents, int quantity, int discountPercent)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(unitPriceCents);
        ArgumentOutOfRangeException.ThrowIfNegative(quantity);
        if (discountPercent < 0 || discountPercent > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(discountPercent), "Discount must be between 0 and 100.");
        }

        long gross = (long)unitPriceCents * quantity;
        long discount = (gross * discountPercent) / 100;
        return checked((int)(gross - discount));
    }
}
