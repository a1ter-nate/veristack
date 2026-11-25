using System;
using System.IO;
using System.Linq;

namespace Examples.Clean;

public sealed class SafeOssHardening
{
    public int ClampThreads(int value, int minFloor) => Math.Max(value, minFloor);

    public int[] OrderedPage(IQueryable<int> query) => query.OrderBy(x => x).Skip(10).Take(5).ToArray();

    public string ReadDisposedReader(string path)
    {
        using var reader = new StreamReader(path);
        return reader.ReadToEnd();
    }
}
