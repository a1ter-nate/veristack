using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace VStack.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class ExplicitStateMachineAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "VSTACK002";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        "Disallow implicit state machines",
        "Implicit state machine detected ({0}): {1}",
        "VerificationStack.Architecture",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly Regex LifecycleBoolPattern = new(
        @"^(?:is(?:Running|Armed|Stopped|Draining|Loading|Error|Errored|Pending|Complete|Completed|Closed|Cancelled|Canceled|Connected|Disconnected|Paused|Ready|Open|Opened|Idle|Active|Busy|Starting|Stopping|Retrying|Failed|Succeeded|Aborted|Expired|Reverted|Locked|Unlocked|Initialized|Disposed|Healthy|Degraded)|has(?:Started|Failed|Finished|Completed|Closed|Cancelled|Canceled|Errored|Connected|TimedOut|Expired|Reverted|Stopped|Succeeded)|was(?:Reverted|Cancelled|Canceled|Stopped|Closed|Aborted|Failed|Started)|aborted|armed|draining|saturated|stopping|starting|reverted|expired|active|running|stopped|loading|pending|closed|cancelled|canceled|connected|paused|completed|failed|disposed)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex StateDiscriminantPattern = new(
        @"^(?:Status|State|Phase|Stage|Mode)$",
        RegexOptions.Compiled);

    private static readonly Regex MutableStateMemberPattern = new(
        @"^_?(?:status|state|phase|stage)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ConfigTypeSuffix = new(
        @"(?:Options|Config|Configuration|Settings|Flags|Args|Params|Props|Input|Query|Filter)$",
        RegexOptions.Compiled);

    private static readonly Regex CanonicalTransitionPattern = new(
        @"^(?:Transition|Reduce|ApplyEvent|NextState|StepState|HandleEvent|TryTransition)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SwitchTargetNamePattern = new(
        @"^_?(?:status|state|phase|stage|kind)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSymbolAction(AnalyzeNamedType, SymbolKind.NamedType);
        context.RegisterSyntaxNodeAction(AnalyzeSwitchStatement, SyntaxKind.SwitchStatement);
        context.RegisterSyntaxNodeAction(AnalyzeSwitchExpression, SyntaxKind.SwitchExpression);
    }

    private static void AnalyzeNamedType(SymbolAnalysisContext context)
    {
        if (context.Symbol is not INamedTypeSymbol type) return;
        if (type.TypeKind != TypeKind.Class && type.TypeKind != TypeKind.Struct) return;
        if (type.IsImplicitlyDeclared) return;

        var location = type.Locations.FirstOrDefault(l => l.IsInSource);
        if (location is null) return;

        var (lifecycleBools, discriminantName, nullableSiblings) = InspectTypeMembers(type);

        if (lifecycleBools.Count >= 2)
        {
            var fields = string.Join(", ", lifecycleBools.OrderBy(n => n, StringComparer.Ordinal).Take(5));
            var states = 1 << Math.Min(lifecycleBools.Count, 20);
            context.ReportDiagnostic(Diagnostic.Create(
                Rule,
                location,
                "implicit-sm-boolean-soup",
                $"{type.Name} declares {lifecycleBools.Count} lifecycle bool flags ({fields}) admitting {states} states; collapse into a closed abstract record hierarchy"));
        }

        if (discriminantName is not null && nullableSiblings.Count >= 2)
        {
            var optFields = string.Join(", ", nullableSiblings.OrderBy(n => n, StringComparer.Ordinal).Take(5));
            context.ReportDiagnostic(Diagnostic.Create(
                Rule,
                location,
                "implicit-sm-optional-bag",
                $"{type.Name} pairs '{discriminantName}' with {nullableSiblings.Count} nullable payload fields ({optFields}); split into per-state sealed record variants"));
        }

        AnalyzeScatteredMutations(context, type);
    }

    private static (HashSet<string> LifecycleBools, string? DiscriminantName, HashSet<string> NullableSiblings) InspectTypeMembers(INamedTypeSymbol type)
    {
        var lifecycleBools = new HashSet<string>(StringComparer.Ordinal);
        string? discriminantName = null;
        var nullableSiblings = new HashSet<string>(StringComparer.Ordinal);
        if (type is null) return (lifecycleBools, discriminantName, nullableSiblings);

        foreach (var member in type.GetMembers())
        {
            if (member.IsImplicitlyDeclared || member.IsStatic) continue;

            ITypeSymbol? memberType = member switch
            {
                IPropertySymbol prop => prop.Type,
                IFieldSymbol field when field.AssociatedSymbol is null => field.Type,
                _ => null,
            };

            if (memberType is null) continue;

            var bareName = member.Name.TrimStart('_');
            if (memberType.SpecialType == SpecialType.System_Boolean && LifecycleBoolPattern.IsMatch(bareName))
            {
                lifecycleBools.Add(member.Name);
            }

            var isNullable = memberType.NullableAnnotation == NullableAnnotation.Annotated ||
                             memberType.OriginalDefinition.SpecialType == SpecialType.System_Nullable_T;

            if (!isNullable && StateDiscriminantPattern.IsMatch(bareName))
            {
                if (!(bareName == "Mode" && ConfigTypeSuffix.IsMatch(type.Name)))
                {
                    discriminantName = member.Name;
                }
            }
            else if (isNullable)
            {
                nullableSiblings.Add(member.Name);
            }
        }

        return (lifecycleBools, discriminantName, nullableSiblings);
    }

    private static void AnalyzeScatteredMutations(SymbolAnalysisContext context, INamedTypeSymbol type)
    {
        if (type is null) return;
        var mutatingMethods = new Dictionary<string, Location>(StringComparer.Ordinal);

        foreach (var syntaxRef in type.DeclaringSyntaxReferences)
        {
            var decl = syntaxRef.GetSyntax(context.CancellationToken);
            foreach (var assignment in decl.DescendantNodes().OfType<AssignmentExpressionSyntax>())
            {
                if (!assignment.IsKind(SyntaxKind.SimpleAssignmentExpression))
                {
                    continue;
                }

                var targetName = ExtractAssignedMemberName(assignment.Left);
                if (targetName is null || !MutableStateMemberPattern.IsMatch(targetName))
                {
                    continue;
                }

                var method = assignment.FirstAncestorOrSelf<MethodDeclarationSyntax>();
                if (method is null)
                {
                    continue;
                }

                var methodName = method.Identifier.ValueText;
                if (CanonicalTransitionPattern.IsMatch(methodName))
                {
                    continue;
                }

                if (!mutatingMethods.ContainsKey(methodName))
                {
                    mutatingMethods[methodName] = assignment.GetLocation();
                }
            }
        }

        if (mutatingMethods.Count >= 2)
        {
            var ordered = mutatingMethods.OrderBy(kv => kv.Key, StringComparer.Ordinal).ToList();
            var names = string.Join(", ", ordered.Select(kv => kv.Key).Take(5));
            context.ReportDiagnostic(Diagnostic.Create(
                Rule,
                ordered[0].Value,
                "implicit-sm-scattered-mutation",
                $"{type.Name} mutates state directly across {mutatingMethods.Count} methods ({names}); centralize transitions in a single pure Transition(state, evt) method"));
        }
    }

    private static string? ExtractAssignedMemberName(ExpressionSyntax left) =>
        left switch
        {
            IdentifierNameSyntax id => id.Identifier.ValueText,
            MemberAccessExpressionSyntax member => member.Name.Identifier.ValueText,
            _ => null,
        };

    private static void AnalyzeSwitchStatement(SyntaxNodeAnalysisContext context)
    {
        var sw = (SwitchStatementSyntax)context.Node;
        if (!IsStateSwitchExpression(sw.Expression, context.SemanticModel, context.CancellationToken))
        {
            return;
        }

        var defaultSection = sw.Sections.FirstOrDefault(s => s.Labels.OfType<DefaultSwitchLabelSyntax>().Any());
        var hasThrowingDefault = defaultSection is not null &&
            (defaultSection.DescendantNodes().OfType<ThrowStatementSyntax>().Any() ||
             defaultSection.DescendantNodes().OfType<ThrowExpressionSyntax>().Any());

        if (!hasThrowingDefault)
        {
            context.ReportDiagnostic(Diagnostic.Create(
                Rule,
                sw.SwitchKeyword.GetLocation(),
                "implicit-sm-non-exhaustive-switch",
                $"switch ({sw.Expression}) lacks an explicit throwing default guard (e.g. default: throw new UnreachableException(...))"));
        }
    }

    private static void AnalyzeSwitchExpression(SyntaxNodeAnalysisContext context)
    {
        var sw = (SwitchExpressionSyntax)context.Node;
        if (!IsStateSwitchExpression(sw.GoverningExpression, context.SemanticModel, context.CancellationToken))
        {
            return;
        }

        var hasDiscardThrow = sw.Arms.Any(arm =>
            arm.Pattern is DiscardPatternSyntax && arm.Expression is ThrowExpressionSyntax);

        if (!hasDiscardThrow)
        {
            context.ReportDiagnostic(Diagnostic.Create(
                Rule,
                sw.SwitchKeyword.GetLocation(),
                "implicit-sm-non-exhaustive-switch",
                $"switch expression on '{sw.GoverningExpression}' lacks an explicit '_ => throw ...' exhaustiveness arm"));
        }
    }

    private static bool IsStateSwitchExpression(
        ExpressionSyntax expr,
        SemanticModel semanticModel,
        System.Threading.CancellationToken cancellationToken)
    {
        var name = expr switch
        {
            IdentifierNameSyntax id => id.Identifier.ValueText,
            MemberAccessExpressionSyntax member => member.Name.Identifier.ValueText,
            _ => null,
        };

        if (name is not null && SwitchTargetNamePattern.IsMatch(name))
        {
            return true;
        }

        var typeInfo = semanticModel.GetTypeInfo(expr, cancellationToken).Type;
        if (typeInfo is null)
        {
            return false;
        }

        return typeInfo.TypeKind == TypeKind.Enum || (typeInfo.IsRecord && typeInfo.IsAbstract);
    }
}
