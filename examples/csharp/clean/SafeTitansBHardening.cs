using System.Collections.Concurrent;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace Examples.Clean;

public sealed class SafeTitansBHardening
{
    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);
    private readonly ConcurrentDictionary<string, Task<string>> _cache = new();

    public Task<string> GetCachedAsync(string key, System.Func<string, Task<string>> loaderAsync)
    {
        var task = _cache.GetOrAdd(key, k => loaderAsync(k));
        _ = task.ContinueWith(
            _ => _cache.TryRemove(key, out var _),
            TaskContinuationOptions.OnlyOnFaulted);
        return task;
    }

    public void WritePayload(Stream output, string payload)
    {
        using var writer = new StreamWriter(output, Utf8NoBom, 1024, leaveOpen: true);
        writer.Write(payload);
    }
}
