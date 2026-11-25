using Xunit;

namespace VStack.Analyzers.Tests;

public sealed class VStackAnalyzersTests
{
    [Fact]
    public async Task VStack001_FlagsProseComments_AndAllowsTagsAndPublicXmlDocs()
    {
        const string bad = """
            public sealed class MathOps
            {
                // increment by one
                public int Inc(int x)
                {
                    /* temporary workaround */
                    return x + 1;
                }
            }
            """;

        var badDiags = await AnalyzerTestHarness.RunAsync(bad, new NoCommentsAnalyzer());
        Assert.Equal(2, badDiags.Length);
        Assert.All(badDiags, d => Assert.Equal("VSTACK001", d.Id));

        const string good = """
            // SPDX-License-Identifier: MIT
            /// <summary>Public contract summary.</summary>
            public sealed class MathOps
            {
                public int Inc(int x)
                {
                    // WARNING: unchecked overflow wraps by design
                    // SAFETY: callers validate upper bound at edge
                    return x + 1;
                }
            }
            """;

        var goodDiags = await AnalyzerTestHarness.RunAsync(good, new NoCommentsAnalyzer());
        Assert.Empty(goodDiags);
    }

    [Fact]
    public async Task VStack002_FlagsBooleanSoup_AndPassesExplicitRecordHierarchy()
    {
        const string bad = """
            public sealed class Watchdog
            {
                public bool IsRunning { get; set; }
                public bool IsArmed { get; set; }
            }
            """;

        var badDiags = await AnalyzerTestHarness.RunAsync(bad, new ExplicitStateMachineAnalyzer());
        var diag = Assert.Single(badDiags);
        Assert.Equal("VSTACK002", diag.Id);
        Assert.Contains("implicit-sm-boolean-soup", diag.GetMessage(), StringComparison.Ordinal);

        const string good = """
            public abstract record WatchdogState
            {
                private WatchdogState() { }
                public sealed record Idle : WatchdogState;
                public sealed record Armed(long ArmedAtUtc) : WatchdogState;
            }
            """;

        var goodDiags = await AnalyzerTestHarness.RunAsync(good, new ExplicitStateMachineAnalyzer());
        Assert.Empty(goodDiags);
    }

    [Fact]
    public async Task VStack002_FlagsNullableStateBag_AndIgnoresPlainConfigDto()
    {
        const string bad = """
            public enum RunStatus { Running, Stopped, Failed }

            public sealed record RunRecord(
                RunStatus Status,
                string? Error,
                long? FinishedAtUtc);
            """;

        var badDiags = await AnalyzerTestHarness.RunAsync(bad, new ExplicitStateMachineAnalyzer());
        var diag = Assert.Single(badDiags);
        Assert.Equal("VSTACK002", diag.Id);
        Assert.Contains("implicit-sm-optional-bag", diag.GetMessage(), StringComparison.Ordinal);

        const string cleanConfig = """
            public enum RunMode { Local, Ci }

            public sealed record RunnerOptions(
                RunMode Mode,
                bool EnableCache,
                bool Verbose,
                bool DryRun,
                string? Endpoint,
                int? TimeoutMs);
            """;

        var cleanDiags = await AnalyzerTestHarness.RunAsync(cleanConfig, new ExplicitStateMachineAnalyzer());
        Assert.Empty(cleanDiags);
    }

    [Fact]
    public async Task VStack002_FlagsScatteredMutations_AndPassesCanonicalTransition()
    {
        const string bad = """
            public enum JobStatus { Idle, Running, Stopped }

            public sealed class Runner
            {
                public JobStatus Status { get; private set; } = JobStatus.Idle;
                public void Start() { Status = JobStatus.Running; }
                public void Stop() { Status = JobStatus.Stopped; }
            }
            """;

        var badDiags = await AnalyzerTestHarness.RunAsync(bad, new ExplicitStateMachineAnalyzer());
        var diag = Assert.Single(badDiags);
        Assert.Equal("VSTACK002", diag.Id);
        Assert.Contains("implicit-sm-scattered-mutation", diag.GetMessage(), StringComparison.Ordinal);

        const string good = """
            public enum JobStatus { Idle, Running, Stopped }

            public sealed class Runner
            {
                public JobStatus Status { get; private set; } = JobStatus.Idle;
                public void Transition(JobStatus next) { Status = next; }
            }
            """;

        var goodDiags = await AnalyzerTestHarness.RunAsync(good, new ExplicitStateMachineAnalyzer());
        Assert.Empty(goodDiags);
    }

    [Fact]
    public async Task VStack002_FlagsNonExhaustiveSwitch_AndPassesThrowingDefault()
    {
        const string bad = """
            public enum JobStatus { Idle, Running }

            public static class Formatter
            {
                public static string Label(JobStatus status) => status switch
                {
                    JobStatus.Idle => "idle",
                    JobStatus.Running => "running",
                };
            }
            """;

        var badDiags = await AnalyzerTestHarness.RunAsync(bad, new ExplicitStateMachineAnalyzer());
        var diag = Assert.Single(badDiags);
        Assert.Equal("VSTACK002", diag.Id);
        Assert.Contains("implicit-sm-non-exhaustive-switch", diag.GetMessage(), StringComparison.Ordinal);

        const string good = """
            using System.Diagnostics;

            public enum JobStatus { Idle, Running }

            public static class Formatter
            {
                public static string Label(JobStatus status) => status switch
                {
                    JobStatus.Idle => "idle",
                    JobStatus.Running => "running",
                    _ => throw new UnreachableException($"Unhandled status: {status}"),
                };
            }
            """;

        var goodDiags = await AnalyzerTestHarness.RunAsync(good, new ExplicitStateMachineAnalyzer());
        Assert.Empty(goodDiags);
    }

    [Fact]
    public async Task VStack003_FlagsUnjustifiedPragmaSuppressMessageAndEmptyCatch()
    {
        const string bad = """
            using System;
            using System.Diagnostics.CodeAnalysis;

            public sealed class Risky
            {
                [SuppressMessage("Design", "CA1031")]
                public void Run()
                {
            #pragma warning disable CS0168
                    try
                    {
                        var x = 1;
                    }
                    catch (Exception)
                    {
                    }
            #pragma warning restore CS0168
                }
            }
            """;

        var badDiags = await AnalyzerTestHarness.RunAsync(bad, new NoSuppressionOrSwallowingCatchAnalyzer());
        Assert.Equal(3, badDiags.Length);
        Assert.All(badDiags, d => Assert.Equal("VSTACK003", d.Id));

        const string good = """
            using System;
            using System.Diagnostics.CodeAnalysis;

            public sealed class Safe
            {
                [SuppressMessage("Design", "CA1031", Justification = "Boundary translates unexpected errors into Result.Fail")]
                public string Run()
                {
            #pragma warning disable CS0168 // SAFETY: intentional probe variable
                    try
                    {
                        return "ok";
                    }
                    catch (InvalidOperationException ex)
                    {
                        return ex.Message;
                    }
            #pragma warning restore CS0168
                }
            }
            """;

        var goodDiags = await AnalyzerTestHarness.RunAsync(good, new NoSuppressionOrSwallowingCatchAnalyzer());
        Assert.Empty(goodDiags);
    }

    [Fact]
    public async Task VStack004_FlagsTestIntegrityLandmines_AndPassesDeterministicTest()
    {
        const string bad = """
            using System;
            using System.Threading;

            public sealed class FactAttribute : Attribute { public string? Skip { get; set; } }
            public static class Assert
            {
                public static void True(bool v) { }
                public static void Equal<T>(T a, T b) { }
            }

            public sealed class BadTests
            {
                [Fact(Skip = "flaky")]
                public void Landmines()
                {
                    Thread.Sleep(50);
                    Environment.SetEnvironmentVariable("MODE", "1");
                    var now = DateTime.UtcNow;
                    var rng = new Random();
                    Assert.True(true);
                    Assert.Equal(Calc(2), Calc(2));
                    if (now.Year > 2000)
                    {
                        Assert.Equal(1, rng.Next());
                    }
                }

                private static int Calc(int x) => x * 2;
            }
            """;

        var badDiags = await AnalyzerTestHarness.RunAsync(bad, new TestIntegrityAnalyzer());
        Assert.Equal(8, badDiags.Length);
        Assert.All(badDiags, d => Assert.Equal("VSTACK004", d.Id));

        const string good = """
            using System;

            public sealed class FactAttribute : Attribute { }
            public static class Assert
            {
                public static void Equal<T>(T a, T b) { }
            }

            public sealed class GoodTests
            {
                [Fact]
                public void DeterministicBehavior()
                {
                    var rng = new Random(42);
                    var fixedNow = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
                    Assert.Equal(4, Calc(2));
                    Assert.Equal(2026, fixedNow.Year);
                    Assert.Equal(rng.Next(10), 6);
                }

                private static int Calc(int x) => x * 2;
            }
            """;

        var goodDiags = await AnalyzerTestHarness.RunAsync(good, new TestIntegrityAnalyzer());
        Assert.Empty(goodDiags);
    }
}
