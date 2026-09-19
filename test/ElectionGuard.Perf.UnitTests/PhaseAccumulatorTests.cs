using ElectionGuard.Perf.Cli.Configuration;
using ElectionGuard.Perf.Cli.Measurement;

namespace ElectionGuard.Perf.UnitTests;

public class PhaseAccumulatorTests
{
    [Fact]
    public void ToMetrics_IsZeroBeforeAnyScope()
    {
        var metrics = new PhaseAccumulator(PhaseNames.EncryptBallots).ToMetrics();

        Assert.Equal(0, metrics.WallMs);
        Assert.Equal(0, metrics.AllocatedBytes);
        Assert.Equal(0, metrics.BallotsProcessed);
        Assert.False(metrics.Aborted);
    }

    [Fact]
    public void Enter_AccumulatesTimeAcrossScopes()
    {
        var accumulator = new PhaseAccumulator(PhaseNames.EncryptBallots);

        for (int i = 0; i < 3; i++)
        {
            using (accumulator.Enter())
            {
                Spin();
            }
        }

        Assert.True(accumulator.ToMetrics().WallMs > 0,
            "Three timed scopes recorded no elapsed time.");
    }

    [Fact]
    public void Enter_AccumulatesAllocations()
    {
        var accumulator = new PhaseAccumulator(PhaseNames.EncryptBallots);
        object? sink = null;

        using (accumulator.Enter())
        {
            sink = new byte[4 * 1024 * 1024];
        }

        GC.KeepAlive(sink);
        Assert.True(accumulator.ToMetrics().AllocatedBytes >= 4 * 1024 * 1024,
            "A 4 MB allocation inside the scope was not counted.");
    }

    [Fact]
    public void Enter_IncludesInScopeAllocationsButExcludesAllocationsMadeBetweenScopes()
    {
        var accumulator = new PhaseAccumulator(PhaseNames.EncryptBallots);
        object? sink;

        using (accumulator.Enter())
        {
            sink = new byte[1 * 1024 * 1024];
        }
        GC.KeepAlive(sink);
        var afterFirstScope = accumulator.ToMetrics().AllocatedBytes;

        // Allocated BETWEEN scopes: this must never reach the accumulator.
        sink = new byte[16 * 1024 * 1024];
        GC.KeepAlive(sink);

        using (accumulator.Enter())
        {
            sink = new byte[1 * 1024 * 1024];
        }
        GC.KeepAlive(sink);

        var secondScopeContribution = accumulator.ToMetrics().AllocatedBytes - afterFirstScope;

        // 8 MB sits generously between the 1 MB the second scope itself allocates and the 16 MB
        // allocated between scopes, so ordinary test-harness allocation noise can't trip either
        // bound: the lower bound proves in-scope allocation is counted, the upper bound proves the
        // interstitial 16 MB is not.
        Assert.True(secondScopeContribution >= 1024 * 1024,
            $"Second scope contributed {secondScopeContribution} bytes; its own 1 MB allocation was not counted.");
        Assert.True(secondScopeContribution < 8 * 1024 * 1024,
            $"Second scope contributed {secondScopeContribution} bytes; the 16 MB allocated between scopes leaked into the measurement.");
    }

    [Fact]
    public void RecordBallots_Accumulates()
    {
        var accumulator = new PhaseAccumulator(PhaseNames.EncryptBallots);

        accumulator.RecordBallots(500);
        accumulator.RecordBallots(250);

        Assert.Equal(750, accumulator.BallotsProcessed);
        Assert.Equal(750, accumulator.ToMetrics().BallotsProcessed);
    }

    [Fact]
    public void BudgetExceeded_IsFalseWhenNoBudgetIsSet()
    {
        var accumulator = new PhaseAccumulator(PhaseNames.DecryptTally, budget: null);

        using (accumulator.Enter())
        {
            Spin();
        }

        Assert.False(accumulator.BudgetExceeded);
    }

    [Fact]
    public void BudgetExceeded_IsFalseWhileWithinBudget()
    {
        var accumulator = new PhaseAccumulator(PhaseNames.DecryptTally, TimeSpan.FromHours(1));

        using (accumulator.Enter())
        {
            Spin();
        }

        Assert.False(accumulator.BudgetExceeded);
    }

    [Fact]
    public void BudgetExceeded_IsTrueOnceElapsedPassesTheBudget()
    {
        var accumulator = new PhaseAccumulator(PhaseNames.DecryptTally, TimeSpan.Zero);

        using (accumulator.Enter())
        {
            Spin();
        }

        Assert.True(accumulator.BudgetExceeded);
    }

    [Fact]
    public void MarkAborted_IsRecorded()
    {
        var accumulator = new PhaseAccumulator(PhaseNames.DecryptTally, TimeSpan.Zero);

        accumulator.MarkAborted();

        Assert.True(accumulator.Aborted);
        Assert.True(accumulator.ToMetrics().Aborted);
    }

    private static void Spin()
    {
        var until = DateTime.UtcNow.AddMilliseconds(2);
        while (DateTime.UtcNow < until)
        {
        }
    }
}
