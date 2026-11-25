using System.Collections.Concurrent;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace Examples.Caught;

public sealed class TitansBHardening
{
    private readonly ConcurrentDictionary<string, Task<string>> _cache = new();

    public Task<string> GetCachedAsync(string key, System.Func<string, Task<string>> loaderAsync)
    {
        return _cache.GetOrAdd(key, k => loaderAsync(k));
    }

    public void WritePayload(Stream output, string payload)
    {
        using var writer = new StreamWriter(output, Encoding.UTF8, 1024, leaveOpen: true);
        writer.Write(payload);
    }
}
