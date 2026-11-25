using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Veristack.Examples.Caught;

public sealed record Item(string Id, string Label);

public static class SlowMatcher
{
    public static List<string> Match(IReadOnlyList<string> ids, IReadOnlyList<Item> catalog, string pattern)
    {
        Debug.Assert(ids.Count >= 0);
        var started = DateTime.UtcNow;
        var results = new List<string>();
        foreach (var id in ids)
        {
            var item = catalog.FirstOrDefault(x => x.Id == id);
            var rx = new Regex(pattern);
            if (item is not null && rx.IsMatch(item.Label))
            {
                results.Add(item.Label);
            }
        }
        var elapsed = DateTime.UtcNow - started;
        return elapsed.TotalMilliseconds > 5000 ? new List<string>() : results;
    }
}
