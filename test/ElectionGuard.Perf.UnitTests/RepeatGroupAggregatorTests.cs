using ElectionGuard.Perf.Cli.Configuration;
using ElectionGuard.Perf.Cli.Reporting;
using ElectionGuard.Perf.Cli.Results;

namespace ElectionGuard.Perf.UnitTests;

public class RepeatGroupAggregatorTests
{
    private static RunRecord Record(
        string? repeatGroup = null,
        double encryptWallMs = 1000,
        long encryptAllocated = 1_000_000,
        int ballots = 1000,
        string correctnessStatus = CorrectnessStatus.Passed,
        bool includeDecrypt = false,
        long peakHeapBytes = 1_000_000) => new()
        {
            RunId = Guid.NewGuid().ToString("n")[..6],
            TimestampUtc = DateTimeOffset.UtcNow,
            RepeatGroup = repeatGroup,
            Scenario = new ScenarioInfo
            {
                Id = "medium", ConfigHash = "sha256:same", ManifestHash = "sha256:m",
                BallotCount = ballots, Seed = 1, GuardianN = 3, GuardianK = 2,
                Parallelism = 8, ChunkSize = 500,
            },
            Source = new SourceInfo { Commit = "abc", Branch = "main", Dirty = false },
            Environment = new EnvironmentInfo
            {
                MachineId = "m1", Cpu = "cpu", LogicalCores = 8, RamGb = 32,
                Os = "os", DotNet = "net9", GcMode = "server", BuildConfig = "Release",
            },
            Setup = new SetupInfo { DkgMs = 1 },
            Phases = BuildPhases(encryptWallMs, encryptAllocated, ballots, includeDecrypt),
            Derived = new DerivedMetrics
            {
                MsPerBallotEncrypt = encryptWallMs / Math.Max(1, ballots),
                BallotsPerSec = 1,
                AllocBytesPerBallot = encryptAllocated / (double)Math.Max(1, ballots),
            },
            Memory = new MemoryMetrics
            {
                PeakManagedHeapBytes = peakHeapBytes,
                PeakWorkingSetBytes = peakHeapBytes * 2,
                TotalAllocatedBytes = peakHeapBytes * 3,
            },
            Correctness = new CorrectnessResult { Status = correctnessStatus },
        };

    private static Dictionary<string, PhaseMetrics> BuildPhases(
        double wallMs, long allocated, int ballots, bool includeDecrypt)
    {
        var phases = new Dictionary<string, PhaseMetrics>
        {
            [PhaseNames.EncryptBallots] = new()
            {
                WallMs = wallMs, AllocatedBytes = allocated, Gc = new GcCounts { G0 = 1 },
                BallotsProcessed = ballots,
            },
        };

        if (includeDecrypt)
        {
            phases[PhaseNames.DecryptTally] = new()
            {
                WallMs = 500, AllocatedBytes = 100, Gc = new GcCounts(), BallotsProcessed = ballots,
            };
        }

        return phases;
    }

    [Fact]
    public void Resolve_MediansAThreeMemberGroupToTheMiddleValueNotFirstOrLast()
    {
        const string group = "g1";
        var low = Record(repeatGroup: group, encryptWallMs: 100);
        var mid = Record(repeatGroup: group, encryptWallMs: 200);
        var high = Record(repeatGroup: group, encryptWallMs: 300);
        var all = new List<RunRecord> { low, mid, high };

        var outcome = RepeatGroupAggregator.Resolve(high, all);

        Assert.True(outcome.Aggregated);
        Assert.Equal(3, outcome.GroupSize);
        Assert.Equal(3, outcome.HealthyCount);
        Assert.Equal(200, outcome.Record.Phases[PhaseNames.EncryptBallots].WallMs);
    }

    [Fact]
    public void Resolve_TakesTheLowerMiddleOfAnEvenSizedGroupRatherThanAveraging()
    {
        const string group = "g2";
        var records = new[] { 100.0, 200.0, 300.0, 400.0 }
            .Select(ms => Record(repeatGroup: group, encryptWallMs: ms))
            .ToList();

        var outcome = RepeatGroupAggregator.Resolve(records[^1], records);

        // The two middle values are 200 and 300. The lower one, 200, must win -- not their
        // average, 250, which no run actually produced.
        Assert.Equal(200, outcome.Record.Phases[PhaseNames.EncryptBallots].WallMs);
    }

    [Fact]
    public void Resolve_LeavesARecordWithNoRepeatGroupUnchanged()
    {
        var record = Record(repeatGroup: null);
        var other = Record(repeatGroup: null);

        var outcome = RepeatGroupAggregator.Resolve(record, [record, other]);

        Assert.False(outcome.Aggregated);
        Assert.Same(record, outcome.Record);
        Assert.Equal(1, outcome.GroupSize);
        Assert.Equal(0, outcome.ExcludedCount);
    }

    [Fact]
    public void Resolve_ExcludesAnErroredMemberAndMediansTheRest()
    {
        const string group = "g3";
        var healthyLow = Record(repeatGroup: group, encryptWallMs: 100);
        var errored = Record(
            repeatGroup: group, encryptWallMs: 999_999, correctnessStatus: CorrectnessStatus.Error);
        var healthyHigh = Record(repeatGroup: group, encryptWallMs: 300);
        var all = new List<RunRecord> { healthyLow, errored, healthyHigh };

        var outcome = RepeatGroupAggregator.Resolve(healthyHigh, all);

        Assert.True(outcome.Aggregated);
        Assert.Equal(3, outcome.GroupSize);
        Assert.Equal(2, outcome.HealthyCount);
        Assert.Equal(1, outcome.ExcludedCount);
        // Lower of the two healthy values (100, 300) -- the errored run's 999,999 must not appear.
        Assert.Equal(100, outcome.Record.Phases[PhaseNames.EncryptBallots].WallMs);
    }

    /// <summary>
    /// When every member of the group is unhealthy, nothing is synthesised: the original selection
    /// is returned unaggregated, and RunComparer's existing incomparability check (which already
    /// refuses to judge an Error/Failed run) correctly refuses the comparison on its own.
    /// </summary>
    [Fact]
    public void Resolve_FallsBackToTheOriginalRecordWhenEveryMemberErroredAndRefusesTheComparison()
    {
        const string group = "g4";
        var a = Record(repeatGroup: group, correctnessStatus: CorrectnessStatus.Error);
        var b = Record(repeatGroup: group, correctnessStatus: CorrectnessStatus.Error);
        var c = Record(repeatGroup: group, correctnessStatus: CorrectnessStatus.Failed);
        var all = new List<RunRecord> { a, b, c };

        var outcome = RepeatGroupAggregator.Resolve(c, all);

        Assert.False(outcome.Aggregated);
        Assert.Same(c, outcome.Record);
        Assert.Equal(3, outcome.GroupSize);
        Assert.Equal(0, outcome.HealthyCount);
        Assert.Equal(3, outcome.ExcludedCount);

        var comparisonResult = RunComparer.Compare(outcome.Record, Record(), new Thresholds());
        Assert.False(comparisonResult.Comparable);
    }

    [Fact]
    public void Resolve_DropsAPhasePresentInOnlySomeMembersFromTheSyntheticRecord()
    {
        const string group = "g5";
        var withDecrypt = Record(repeatGroup: group, includeDecrypt: true);
        var withoutDecrypt = Record(repeatGroup: group, includeDecrypt: false);
        var all = new List<RunRecord> { withDecrypt, withoutDecrypt };

        var outcome = RepeatGroupAggregator.Resolve(withoutDecrypt, all);

        Assert.True(outcome.Aggregated);
        Assert.True(outcome.Record.Phases.ContainsKey(PhaseNames.EncryptBallots));
        Assert.False(outcome.Record.Phases.ContainsKey(PhaseNames.DecryptTally));
        Assert.Contains(outcome.Notes, x => x.Contains(PhaseNames.DecryptTally, StringComparison.Ordinal));
    }
}
