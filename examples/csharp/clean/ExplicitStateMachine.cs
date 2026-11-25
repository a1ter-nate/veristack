using System.Diagnostics;

namespace Veristack.Examples.Clean;

public abstract record PaymentState
{
    private PaymentState() { }

    public sealed record Pending(int AmountCents) : PaymentState;
    public sealed record Captured(int AmountCents, string AuthCode) : PaymentState;
    public sealed record Failed(string Reason) : PaymentState;
}

public static class PaymentFormatter
{
    public static string Describe(PaymentState state) => state switch
    {
        PaymentState.Pending p => $"Pending {p.AmountCents}",
        PaymentState.Captured c => $"Captured {c.AuthCode}",
        PaymentState.Failed f => $"Failed: {f.Reason}",
        _ => throw new UnreachableException($"Unhandled state: {state}")
    };
}
