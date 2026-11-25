using System;
using System.Buffers;
using System.Threading;

namespace Examples.Clean;

public sealed class SafeTitansAHardening
{
    private long _active;

    public int ComputeChunk(long remaining, int bufferSize)
    {
        return (int)Math.Min(remaining, bufferSize);
    }

    public int RentSafely(int size)
    {
        var buf = ArrayPool<byte>.Shared.Rent(size);
        try
        {
            return buf.Length;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    public bool TryParseMaxAge(long seconds, out TimeSpan result)
    {
        if (seconds < 0 || seconds > TimeSpan.MaxValue.TotalSeconds)
        {
            result = default;
            return false;
        }
        result = TimeSpan.FromSeconds(seconds);
        return true;
    }

    public bool IsLocalRedirect(string url)
    {
        return url.StartsWith("/") && !url.StartsWith("//") && !url.Contains("\\");
    }

    public bool IsNanSafe(double val)
    {
        return double.IsNaN(val);
    }

    public void WaitSafely(object gate, Func<bool> isReady)
    {
        while (!isReady())
        {
            Monitor.Wait(gate);
        }
    }

    public bool TryAcquireSlot(long maxSlots)
    {
        for (var attempt = 0; attempt < 64; attempt++)
        {
            var current = Interlocked.Read(ref _active);
            if (current >= maxSlots)
            {
                return false;
            }
            if (Interlocked.CompareExchange(ref _active, current + 1, current) == current)
            {
                return true;
            }
        }
        return false;
    }
}
