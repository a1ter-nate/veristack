using System.Diagnostics;
using System.Net.Http;
using System.Threading.Channels;

namespace Demo;

public sealed class BadTigerWorker
{
    public int Run(int count)
    {
        Debug.Assert(count > 0);
        var ch = Channel.CreateUnbounded<int>();
        var client = new HttpClient();
        unchecked
        {
            return count + 1 + ch.GetHashCode() + client.GetHashCode();
        }
    }
}
