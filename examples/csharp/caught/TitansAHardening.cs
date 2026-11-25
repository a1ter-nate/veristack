using System;
using System.Buffers;
using System.Threading;

namespace Examples.Caught;

public sealed class TitansAHardening
{
    private long _active;

    public int ComputeChunk(long remaining, int bufferSize)
    {
        return Math.Min((int)remaining, bufferSize);
    }

    public byte[] RentWithoutFinally(int size)
    {
        var buf = ArrayPool<byte>.Shared.Rent(size);
        ArrayPool<byte>.Shared.Return(buf);
        return buf;
    }

    public bool TryParseMaxAge(long seconds, out TimeSpan result)
    {
        result = TimeSpan.FromSeconds(seconds);
        return true;
    }

    public bool IsLocalRedirect(string url)
    {
        return url.StartsWith("/") && !url.StartsWith("//");
    }

    public bool IsNanBroken(double val)
    {
        return val == double.NaN;
    }

    public void WaitOnce(object gate, bool ready)
    {
        if (!ready)
        {
            Monitor.Wait(gate);
        }
    }

    public bool TryAcquireSlot(long maxSlots)
    {
        if (Interlocked.Read(ref _active) < maxSlots)
        {
            Interlocked.Increment(ref _active);
            return true;
        }
        return false;
    }
}
