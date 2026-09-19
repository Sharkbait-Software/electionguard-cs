using System.Diagnostics;
using ElectionGuard.Perf.Cli.Results;

namespace ElectionGuard.Perf.Cli.Measurement;

/// <summary>
/// Tracks peak managed heap size on a background timer. Sampling is necessary because the peak
/// occurs mid-chunk -- reading the heap only at chunk boundaries reports the trough, since the
/// chunk's ballots have just been dropped.
///
/// Peak working set needs no sampling: the OS tracks it, and Process.PeakWorkingSet64 reports it.
/// </summary>
public sealed class MemorySampler : IDisposable
{
    private readonly Timer _timer;
    private long _peakManagedHeapBytes;
    private bool _disposed;

    public MemorySampler(TimeSpan interval)
    {
        _timer = new Timer(_ => SampleNow(), null, TimeSpan.Zero, interval);
    }

    public long PeakManagedHeapBytes => Interlocked.Read(ref _peakManagedHeapBytes);

    /// <summary>Takes a sample immediately. Called by the timer, and directly by tests.</summary>
    public void SampleNow()
    {
        // Timer.Dispose() does not wait for an in-flight callback, so a callback already running
        // when Dispose is called can still reach here after Dispose returns. That race is harmless
        // -- this only touches a long via Interlocked, on a field that outlives the timer -- so it
        // is left as a silent no-op rather than synchronized away. This guard only makes the no-op
        // explicit for a call arriving after disposal completes.
        if (_disposed)
        {
            return;
        }

        var current = GC.GetTotalMemory(forceFullCollection: false);

        long observed;
        while (current > (observed = Interlocked.Read(ref _peakManagedHeapBytes)))
        {
            if (Interlocked.CompareExchange(ref _peakManagedHeapBytes, current, observed) == observed)
            {
                break;
            }
        }
    }

    public MemoryMetrics Snapshot()
    {
        using var process = Process.GetCurrentProcess();
        process.Refresh();

        return new MemoryMetrics
        {
            PeakManagedHeapBytes = PeakManagedHeapBytes,
            PeakWorkingSetBytes = process.PeakWorkingSet64,
            TotalAllocatedBytes = GC.GetTotalAllocatedBytes(precise: true),
        };
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _timer.Dispose();
    }
}
