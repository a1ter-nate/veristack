using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Veristack.Examples.Clean;

public sealed record CatalogItem(string Id, string Label);

public static class IndexedMatcher
{
    public static IReadOnlyList<string> Match(
        IReadOnlyList<string> ids,
        IReadOnlyList<CatalogItem> catalog,
        string pattern)
    {
        if (ids is null)
        {
            throw new InvalidOperationException("ids invariant violated");
        }
        var started = Stopwatch.GetTimestamp();
        var byId = catalog.ToDictionary(item => item.Id);
        var rx = new Regex(pattern, RegexOptions.NonBacktracking);
        var results = new List<string>();
        foreach (var id in ids)
        {
            if (byId.TryGetValue(id, out var item) && rx.IsMatch(item.Label))
            {
                results.Add(item.Label);
            }
        }
        _ = Stopwatch.GetElapsedTime(started);
        return results;
    }
}
