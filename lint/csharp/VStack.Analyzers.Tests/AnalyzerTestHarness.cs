using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace VStack.Analyzers.Tests;

internal static class AnalyzerTestHarness
{
    private static readonly ImmutableArray<MetadataReference> References = BuildReferences();

    public static async Task<ImmutableArray<Diagnostic>> RunAsync(
        string source,
        params DiagnosticAnalyzer[] analyzers)
    {
        var tree = CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.Latest));
        var compilation = CSharpCompilation.Create(
            "AnalyzerUnderTest",
            new[] { tree },
            References,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, nullableContextOptions: NullableContextOptions.Enable));

        var withAnalyzers = compilation.WithAnalyzers(ImmutableArray.Create(analyzers));
        return await withAnalyzers.GetAnalyzerDiagnosticsAsync().ConfigureAwait(false);
    }

    private static ImmutableArray<MetadataReference> BuildReferences()
    {
        var assemblies = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var references = new List<MetadataReference>();

        void Add(Assembly assembly)
        {
            if (!string.IsNullOrEmpty(assembly.Location) && assemblies.Add(assembly.Location))
            {
                references.Add(MetadataReference.CreateFromFile(assembly.Location));
            }
        }

        Add(typeof(object).Assembly);
        Add(typeof(UnreachableException).Assembly);
        Add(typeof(SuppressMessageAttribute).Assembly);
        Add(typeof(Enumerable).Assembly);

        var trustedDir = Path.GetDirectoryName(typeof(object).Assembly.Location);
        if (trustedDir is not null)
        {
            foreach (var name in new[] { "System.Runtime.dll", "netstandard.dll" })
            {
                var full = Path.Combine(trustedDir, name);
                if (File.Exists(full) && assemblies.Add(full))
                {
                    references.Add(MetadataReference.CreateFromFile(full));
                }
            }
        }

        return references.ToImmutableArray();
    }
}
