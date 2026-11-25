using System;
using System.IO;
using System.Linq;

namespace Examples.Caught;

public sealed class OssHardening
{
    public int ClampThreads(int value, int minFloor) => Math.Min(value, minFloor);

    public int[] UnorderedPage(IQueryable<int> query) => query.Skip(10).Take(5).ToArray();

    public string ReadLeakingReader(string path)
    {
        var reader = new StreamReader(path);
        return reader.ReadToEnd();
    }
}
