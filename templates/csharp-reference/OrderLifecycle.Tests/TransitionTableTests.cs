using System.Diagnostics;
using System.Text.Json;
using OrderLifecycle.Domain;
using Xunit;

namespace OrderLifecycle.Tests;

public sealed record TransitionRow(
    string Name,
    string Initial,
    string Event,
    string Arg,
    bool Accepted,
    string Expected,
    string ErrorCode);

public sealed class TransitionTableTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public static IEnumerable<object[]> TransitionCases()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "fixtures", "transitions.json");
        var rows = JsonSerializer.Deserialize<List<TransitionRow>>(File.ReadAllText(path), JsonOptions)
            ?? throw new InvalidOperationException("Missing transitions.json fixture.");

        foreach (var row in rows)
        {
            yield return new object[] { row };
        }
    }

    [Theory]
    [MemberData(nameof(TransitionCases))]
    public void TransitionMatrix_MatchesTestsAsDataTable(TransitionRow row)
    {
        var initial = BuildState(row.Initial);
        var evt = BuildEvent(row.Event, row.Arg);

        var outcome = OrderStateMachine.Transition(initial, evt);

        if (row.Accepted)
        {
            var accepted = Assert.IsType<TransitionOutcome.Accepted>(outcome);
            Assert.Equal(row.Expected, OrderStateMachine.NameOf(accepted.NextState));
        }
        else
        {
            var rejected = Assert.IsType<TransitionOutcome.Rejected>(outcome);
            Assert.Equal(row.ErrorCode, rejected.Code);
            Assert.Equal(row.Expected, OrderStateMachine.NameOf(rejected.UnchangedState));
            Assert.Equal(initial, rejected.UnchangedState);
        }
    }

    private static OrderState BuildState(string name) =>
        name switch
        {
            "pending" => new OrderState.Pending(1_500),
            "authorized" => new OrderState.Authorized(1_500, "AUTH-0"),
            "shipped" => new OrderState.Shipped(1_500, "AUTH-0", "TRK-0"),
            "cancelled" => new OrderState.Cancelled("init"),
            _ => throw new UnreachableException($"Unknown state fixture: {name}"),
        };

    private static OrderEvent BuildEvent(string name, string arg) =>
        name switch
        {
            "authorize" => new OrderEvent.Authorize(arg),
            "ship" => new OrderEvent.Ship(arg),
            "cancel" => new OrderEvent.Cancel(arg),
            _ => throw new UnreachableException($"Unknown event fixture: {name}"),
        };
}
