using ElectionGuard.Perf.Cli.Measurement;

namespace ElectionGuard.Perf.UnitTests;

public class MemorySamplerTests
{
    [Fact]
    public void SampleNow_RecordsAPeakAboveZero()
    {
        using var sampler = new MemorySampler(TimeSpan.FromMilliseconds(50));

        sampler.SampleNow();

        Assert.True(sampler.PeakManagedHeapBytes > 0);
    }

    [Fact]
    public void SampleNow_TracksTheMaximumRatherThanTheLatest()
    {
        using var sampler = new MemorySampler(TimeSpan.FromMilliseconds(50));

        var big = new byte[64 * 1024 * 1024];
        GC.KeepAlive(big);
        sampler.SampleNow();
        var peakWhileHeld = sampler.PeakManagedHeapBytes;

        big = null;
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        sampler.SampleNow();

        Assert.Equal(peakWhileHeld, sampler.PeakManagedHeapBytes);
    }

    [Fact]
    public void Snapshot_ReportsPeakWorkingSetAndTotalAllocations()
    {
        using var sampler = new MemorySampler(TimeSpan.FromMilliseconds(50));
        sampler.SampleNow();

        var snapshot = sampler.Snapshot();

        Assert.True(snapshot.PeakManagedHeapBytes > 0);
        Assert.True(snapshot.PeakWorkingSetBytes > 0);
        Assert.True(snapshot.TotalAllocatedBytes > 0);
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var sampler = new MemorySampler(TimeSpan.FromMilliseconds(50));

        sampler.Dispose();
        sampler.Dispose();
    }
}
