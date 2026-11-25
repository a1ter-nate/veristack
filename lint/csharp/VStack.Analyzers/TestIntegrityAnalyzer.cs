using System;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace VStack.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class TestIntegrityAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "VSTACK004";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        "Enforce deterministic, non-tautological C# tests",
        "Test integrity violation ({0}): {1}",
        "VerificationStack.Testing",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly ImmutableHashSet<string> TestAttributes = ImmutableHashSet.Create(
        StringComparer.Ordinal,
        "Fact",
        "FactAttribute",
        "Theory",
        "TheoryAttribute",
        "Test",
        "TestAttribute",
        "TestMethod",
        "TestMethodAttribute",
        "Property",
        "PropertyAttribute");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxNodeAction(AnalyzeMethod, SyntaxKind.MethodDeclaration);
    }

    private static void AnalyzeMethod(SyntaxNodeAnalysisContext context)
    {
        var method = (MethodDeclarationSyntax)context.Node;
        if (!IsTestMethod(method, out var skippedAttr))
        {
            return;
        }

        if (skippedAttr is not null)
        {
            context.ReportDiagnostic(Diagnostic.Create(
                Rule,
                skippedAttr.GetLocation(),
                "test-discipline",
                "skipped or ignored test committed; fix or delete the test instead of disabling it"));
        }

        var body = (SyntaxNode?)method.Body ?? method.ExpressionBody;
        if (body is null)
        {
            return;
        }

        foreach (var invocation in body.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            var exprText = invocation.Expression.ToString();

            if (exprText.EndsWith("Thread.Sleep", StringComparison.Ordinal) ||
                exprText.EndsWith("Task.Delay", StringComparison.Ordinal))
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    Rule,
                    invocation.GetLocation(),
                    "no-fixed-sleep",
                    "fixed sleep in test causes flakiness and slows CI; await an explicit signal or TaskCompletionSource"));
            }

            if (exprText.EndsWith("Environment.SetEnvironmentVariable", StringComparison.Ordinal))
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    Rule,
                    invocation.GetLocation(),
                    "no-imported-mutation",
                    "mutating process environment leaks across parallel tests; inject configuration via constructor/options"));
            }

            if (exprText.EndsWith("Assert.Pass", StringComparison.Ordinal))
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    Rule,
                    invocation.GetLocation(),
                    "weak-asserts-tautology",
                    "Assert.Pass() cannot fail when production behavior breaks"));
            }

            if ((exprText.EndsWith("Assert.True", StringComparison.Ordinal) ||
                 exprText.EndsWith("Assert.IsTrue", StringComparison.Ordinal)) &&
                invocation.ArgumentList.Arguments.Count >= 1 &&
                invocation.ArgumentList.Arguments[0].Expression.IsKind(SyntaxKind.TrueLiteralExpression))
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    Rule,
                    invocation.GetLocation(),
                    "weak-asserts-tautology",
                    "tautological Assert.True(true) cannot detect regressions"));
            }

            if ((exprText.EndsWith("Assert.Equal", StringComparison.Ordinal) ||
                 exprText.EndsWith("Assert.StrictEqual", StringComparison.Ordinal) ||
                 exprText.EndsWith("Assert.AreEqual", StringComparison.Ordinal)) &&
                invocation.ArgumentList.Arguments.Count >= 2)
            {
                var left = invocation.ArgumentList.Arguments[0].Expression.ToString().Trim();
                var right = invocation.ArgumentList.Arguments[1].Expression.ToString().Trim();
                if (string.Equals(left, right, StringComparison.Ordinal))
                {
                    context.ReportDiagnostic(Diagnostic.Create(
                        Rule,
                        invocation.GetLocation(),
                        "self-derived-expectation",
                        $"expected and actual compare the identical expression '{left}'; use an independent oracle"));
                }
            }
        }

        foreach (var member in body.DescendantNodes().OfType<MemberAccessExpressionSyntax>())
        {
            var text = member.ToString();
            if (text.EndsWith("DateTime.Now", StringComparison.Ordinal) ||
                text.EndsWith("DateTime.UtcNow", StringComparison.Ordinal) ||
                text.EndsWith("DateTimeOffset.Now", StringComparison.Ordinal) ||
                text.EndsWith("DateTimeOffset.UtcNow", StringComparison.Ordinal) ||
                text.EndsWith("Random.Shared", StringComparison.Ordinal))
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    Rule,
                    member.GetLocation(),
                    "no-test-nondeterminism",
                    $"ambient clock/RNG '{text}' makes tests nondeterministic; inject TimeProvider or a fixed seed"));
            }
        }

        foreach (var creation in body.DescendantNodes().OfType<ObjectCreationExpressionSyntax>())
        {
            if (creation.Type.ToString().EndsWith("Random", StringComparison.Ordinal) &&
                (creation.ArgumentList is null || creation.ArgumentList.Arguments.Count == 0))
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    Rule,
                    creation.GetLocation(),
                    "no-test-nondeterminism",
                    "unseeded new Random() is nondeterministic; pass a constant seed or use FsCheck"));
            }
        }

        foreach (var ifStmt in body.DescendantNodes().OfType<IfStatementSyntax>())
        {
            if (ifStmt.Else is not null)
            {
                continue;
            }

            var hasAssert = ifStmt.Statement.DescendantNodes().OfType<InvocationExpressionSyntax>()
                .Any(inv => inv.Expression.ToString().StartsWith("Assert.", StringComparison.Ordinal));
            if (hasAssert)
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    Rule,
                    ifStmt.IfKeyword.GetLocation(),
                    "no-conditional-expect",
                    "assertion inside one-sided if branch silently passes when branch is skipped; make assertions unconditional"));
            }
        }
    }

    private static bool IsTestMethod(MethodDeclarationSyntax method, out AttributeSyntax? skippedAttr)
    {
        skippedAttr = null;
        var isTest = false;
        foreach (var attr in method.AttributeLists.SelectMany(list => list.Attributes))
        {
            var rawName = attr.Name.ToString();
            var shortName = rawName.Contains('.') ? rawName.Substring(rawName.LastIndexOf('.') + 1) : rawName;
            if (TestAttributes.Contains(shortName))
            {
                isTest = true;
                var hasSkip = attr.ArgumentList?.Arguments.Any(a => a.NameEquals?.Name.Identifier.ValueText == "Skip") == true;
                if (hasSkip)
                {
                    skippedAttr = attr;
                }
            }

            if (shortName is "Ignore" or "IgnoreAttribute")
            {
                isTest = true;
                skippedAttr = attr;
            }
        }

        return isTest;
    }
}
