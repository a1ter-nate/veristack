using System;
using System.Collections.Immutable;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace VStack.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class NoSuppressionOrSwallowingCatchAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "VSTACK003";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        "Disallow unjustified warning suppressions and swallowing catch blocks",
        "Reliability gate violation: {0}",
        "VerificationStack.Reliability",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly Regex PragmaReasonPattern = new(
        @"(?://\s*(?:WARNING|SAFETY):|--\s*\S)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxTreeAction(AnalyzePragmas);
        context.RegisterSyntaxNodeAction(AnalyzeAttribute, SyntaxKind.Attribute);
        context.RegisterSyntaxNodeAction(AnalyzeCatchClause, SyntaxKind.CatchClause);
    }

    private static void AnalyzePragmas(SyntaxTreeAnalysisContext context)
    {
        var root = context.Tree.GetRoot(context.CancellationToken);
        foreach (var directive in root.DescendantTrivia(descendIntoTrivia: true))
        {
            if (!directive.IsKind(SyntaxKind.PragmaWarningDirectiveTrivia))
            {
                continue;
            }

            if (directive.GetStructure() is not PragmaWarningDirectiveTriviaSyntax pragma ||
                !pragma.DisableOrRestoreKeyword.IsKind(SyntaxKind.DisableKeyword))
            {
                continue;
            }

            var lineText = context.Tree.GetText(context.CancellationToken)
                .Lines.GetLineFromPosition(pragma.SpanStart).ToString();

            if (!PragmaReasonPattern.IsMatch(lineText))
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    Rule,
                    pragma.GetLocation(),
                    "#pragma warning disable without a // WARNING: or // SAFETY: justification"));
            }
        }
    }

    private static void AnalyzeAttribute(SyntaxNodeAnalysisContext context)
    {
        var attr = (AttributeSyntax)context.Node;
        var name = attr.Name.ToString();
        if (!name.EndsWith("SuppressMessage", StringComparison.Ordinal) &&
            !name.EndsWith("SuppressMessageAttribute", StringComparison.Ordinal))
        {
            return;
        }

        var args = attr.ArgumentList?.Arguments;
        var hasJustification = args is not null && args.Value.Any(arg =>
            arg.NameEquals?.Name.Identifier.ValueText == "Justification" &&
            arg.Expression is LiteralExpressionSyntax lit &&
            lit.IsKind(SyntaxKind.StringLiteralExpression) &&
            !string.IsNullOrWhiteSpace(lit.Token.ValueText));

        if (!hasJustification)
        {
            context.ReportDiagnostic(Diagnostic.Create(
                Rule,
                attr.GetLocation(),
                "[SuppressMessage] requires a non-empty Justification = \"...\" explaining the invariant"));
        }
    }

    private static void AnalyzeCatchClause(SyntaxNodeAnalysisContext context)
    {
        var clause = (CatchClauseSyntax)context.Node;
        if (clause.Block.Statements.Count == 0)
        {
            context.ReportDiagnostic(Diagnostic.Create(
                Rule,
                clause.CatchKeyword.GetLocation(),
                "empty catch block silently swallows exceptions; rethrow, return a typed error, or handle explicitly"));
        }
    }
}
