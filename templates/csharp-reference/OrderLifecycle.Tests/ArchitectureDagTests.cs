using OrderLifecycle.Domain;
using Xunit;

namespace OrderLifecycle.Tests;

public sealed class ArchitectureDagTests
{
    private static readonly string[] ForbiddenPrefixes =
    {
        "Microsoft.EntityFrameworkCore",
        "Microsoft.AspNetCore",
        "System.Net.Http",
        "Npgsql",
        "Azure.",
        "xunit",
        "FsCheck",
    };

    [Fact]
    public void DomainAssembly_HasZeroInfrastructureOrTestDependencies()
    {
        var domainAssembly = typeof(OrderState).Assembly;
        var referenced = domainAssembly.GetReferencedAssemblies().Select(a => a.Name ?? string.Empty).ToArray();

        foreach (var name in referenced)
        {
            Assert.DoesNotContain(ForbiddenPrefixes, prefix => name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
        }
    }
}
