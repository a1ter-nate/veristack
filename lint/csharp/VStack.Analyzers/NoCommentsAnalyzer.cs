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
public sealed class NoCommentsAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "VSTACK001";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        "Disallow prose and excuse comments",
        "Prose comment is disallowed; express intent in names/types or prefix real footguns with WARNING: or SAFETY:",
        "VerificationStack.Style",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly Regex GeneratedPattern = new(
        @"<(?:auto-)?generated\b|auto-generated|generated code|\bdo not (?:manually )?edit\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex LegalPattern = new(
        @"\b(?:spdx-license-identifier:|copyright\b|licensed under\b|all rights reserved\b)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex DirectivePattern = new(
        @"^(?:ReSharper\b|nullable\b|pragma\b|NOSONAR\b|CodeQL\b)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex AllowedTagPattern = new(
        @"^(?:WARNING|SAFETY):",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxTreeAction(AnalyzeTree);
    }

    private static void AnalyzeTree(SyntaxTreeAnalysisContext context)
    {
        if (context.Tree is null) return;
        var root = context.Tree.GetRoot(context.CancellationToken);
        var firstToken = root.GetFirstToken();
        var firstCodePos = firstToken.SpanStart;

        var triviaList = root.DescendantTrivia(descendIntoTrivia: false).ToList();
        foreach (var trivia in triviaList)
        {
            if (trivia.SpanStart >= firstCodePos)
            {
                break;
            }

            if (IsStandardComment(trivia) && GeneratedPattern.IsMatch(NormalizeComment(trivia.ToString())))
            {
                return;
            }
        }

        foreach (var trivia in triviaList)
        {
            if (trivia.IsKind(SyntaxKind.SingleLineDocumentationCommentTrivia) ||
                trivia.IsKind(SyntaxKind.MultiLineDocumentationCommentTrivia))
            {
                if (!IsPublicDeclarationDoc(trivia))
                {
                    context.ReportDiagnostic(Diagnostic.Create(Rule, trivia.GetLocation()));
                }

                continue;
            }

            if (!IsStandardComment(trivia))
            {
                continue;
            }

            var body = NormalizeComment(trivia.ToString());
            if (string.IsNullOrWhiteSpace(body))
            {
                continue;
            }

            var isHeader = trivia.SpanStart < firstCodePos;
            if (isHeader && (LegalPattern.IsMatch(body) || GeneratedPattern.IsMatch(body)))
            {
                continue;
            }

            if (DirectivePattern.IsMatch(body) || AllowedTagPattern.IsMatch(body))
            {
                continue;
            }

            context.ReportDiagnostic(Diagnostic.Create(Rule, trivia.GetLocation()));
        }
    }

    private static bool IsStandardComment(SyntaxTrivia trivia) =>
        trivia.IsKind(SyntaxKind.SingleLineCommentTrivia) || trivia.IsKind(SyntaxKind.MultiLineCommentTrivia);

    private static bool IsPublicDeclarationDoc(SyntaxTrivia trivia)
    {
        var token = trivia.Token;
        for (var node = token.Parent; node is not null; node = node.Parent)
        {
            if (node is MemberDeclarationSyntax member)
            {
                return member.Modifiers.Any(m => m.IsKind(SyntaxKind.PublicKeyword));
            }
        }

        return false;
    }

    private static string NormalizeComment(string raw)
    {
        var trimmed = raw.Trim();
        if (trimmed.StartsWith("//", StringComparison.Ordinal))
        {
            return trimmed.TrimStart('/').Trim();
        }

        if (trimmed.StartsWith("/*", StringComparison.Ordinal) && trimmed.EndsWith("*/", StringComparison.Ordinal))
        {
            var inner = trimmed.Substring(2, trimmed.Length - 4);
            var lines = inner.Split('\n').Select(l => l.Trim().TrimStart('*').Trim());
            return string.Join("\n", lines).Trim();
        }

        return trimmed;
    }
}
