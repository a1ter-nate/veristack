using System;
using System.Net.Http;
using System.Threading.Channels;

namespace Demo;

public sealed class SafeTigerWorker
{
    public int Run(int count, int timeoutMsMax)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(count);
        var ch = Channel.CreateBounded<int>(new BoundedChannelOptions(64));
        using var client = new HttpClient { Timeout = TimeSpan.FromMilliseconds(timeoutMsMax) };
        return checked(count + 1 + ch.GetHashCode() + client.GetHashCode());
    }
}
