using System.Diagnostics;
using ElectionGuard.Perf.Cli.Results;

namespace ElectionGuard.Perf.Cli.Measurement;

/// <summary>
/// Accumulates wall time, allocated bytes and GC counts for one phase across many chunks.
///
/// Allocation is measured with GC.GetTotalAllocatedBytes(precise: true), which is process-wide and
/// therefore correctly captures work done on every thread of a parallel chunk. It is called twice
/// per scope, so scopes must wrap a chunk rather than an individual ballot.
///
/// Not thread-safe: enter a scope on the thread that drives the chunk loop, and let the work inside
/// the scope be parallel.
/// </summary>
public sealed class PhaseAccumulator
{
    private long _ticks;
    private long _allocatedBytes;
    private int _gen0;
    private int _gen1;
    private int _gen2;

    public PhaseAccumulator(string name, TimeSpan? budget = null)
    {
        Name = name;
        Budget = budget;
    }

    public string Name { get; }

    /// <summary>Wall-clock allowance for this phase. Null means unlimited.</summary>
    public TimeSpan? Budget { get; }

    public int BallotsProcessed { get; private set; }

    public bool Aborted { get; private set; }

    public TimeSpan Elapsed => TimeSpan.FromSeconds(_ticks / (double)Stopwatch.Frequency);

    /// <summary>
    /// True once accumulated time has reached the budget. The runner checks this at chunk
    /// boundaries; a phase is never interrupted mid-chunk, so a chunk is the abort granularity.
    /// </summary>
    public bool BudgetExceeded => Budget.HasValue && Elapsed >= Budget.Value;

    public Scope Enter() => new(this);

    public void RecordBallots(int count) => BallotsProcessed += count;

    public void MarkAborted() => Aborted = true;

    public PhaseMetrics ToMetrics() => new()
    {
        WallMs = _ticks * 1000.0 / Stopwatch.Frequency,
        AllocatedBytes = _allocatedBytes,
        Gc = new GcCounts { G0 = _gen0, G1 = _gen1, G2 = _gen2 },
        BallotsProcessed = BallotsProcessed,
        Aborted = Aborted,
    };

    public readonly struct Scope : IDisposable
    {
        private readonly PhaseAccumulator _owner;
        private readonly long _startTicks;
        private readonly long _startAllocated;
        private readonly int _startGen0;
        private readonly int _startGen1;
        private readonly int _startGen2;

        internal Scope(PhaseAccumulator owner)
        {
            _owner = owner;
            _startAllocated = GC.GetTotalAllocatedBytes(precise: true);
            _startGen0 = GC.CollectionCount(0);
            _startGen1 = GC.CollectionCount(1);
            _startGen2 = GC.CollectionCount(2);
            _startTicks = Stopwatch.GetTimestamp();
        }

        public void Dispose()
        {
            _owner._ticks += Stopwatch.GetTimestamp() - _startTicks;
            _owner._allocatedBytes += GC.GetTotalAllocatedBytes(precise: true) - _startAllocated;
            _owner._gen0 += GC.CollectionCount(0) - _startGen0;
            _owner._gen1 += GC.CollectionCount(1) - _startGen1;
            _owner._gen2 += GC.CollectionCount(2) - _startGen2;
        }
    }
}
