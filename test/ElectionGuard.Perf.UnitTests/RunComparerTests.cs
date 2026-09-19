using ElectionGuard.Perf.Cli.Configuration;
using ElectionGuard.Perf.Cli.Reporting;
using ElectionGuard.Perf.Cli.Results;

namespace ElectionGuard.Perf.UnitTests;

public class RunComparerTests
{
    private static readonly Thresholds Default = new();

    private static RunRecord Record(
        double encryptWallMs = 1000,
        long encryptAllocated = 1_000_000,
        int ballots = 1000,
        bool aborted = false,
        string gcMode = "server",
        string buildConfig = "Release",
        string configHash = "sha256:same",
        string manifestHash = "sha256:m",
        string machineId = "m1",
        bool includeDecrypt = false,
        long peakHeapBytes = 1_000_000,
        string correctnessStatus = CorrectnessStatus.Passed) => new()
        {
            RunId = Guid.NewGuid().ToString("n")[..6],
            TimestampUtc = DateTimeOffset.UtcNow,
            Scenario = new ScenarioInfo
            {
                Id = "medium", ConfigHash = configHash, ManifestHash = manifestHash,
                BallotCount = ballots, Seed = 1, GuardianN = 3, GuardianK = 2,
                Parallelism = 8, ChunkSize = 500,
            },
            Source = new SourceInfo { Commit = "abc", Branch = "main", Dirty = false },
            Environment = new EnvironmentInfo
            {
                MachineId = machineId, Cpu = "cpu", LogicalCores = 8, RamGb = 32,
                Os = "os", DotNet = "net9", GcMode = gcMode, BuildConfig = buildConfig,
            },
            Setup = new SetupInfo { DkgMs = 1 },
            Phases = BuildPhases(encryptWallMs, encryptAllocated, ballots, aborted, includeDecrypt),
            Derived = new DerivedMetrics { MsPerBallotEncrypt = 1, BallotsPerSec = 1, AllocBytesPerBallot = 1 },
            Memory = new MemoryMetrics
            {
                PeakManagedHeapBytes = peakHeapBytes, PeakWorkingSetBytes = 2_000_000, TotalAllocatedBytes = 3_000_000,
            },
            Correctness = new CorrectnessResult { Status = correctnessStatus },
        };

    private static Dictionary<string, PhaseMetrics> BuildPhases(
        double wallMs, long allocated, int ballots, bool aborted, bool includeDecrypt)
    {
        var phases = new Dictionary<string, PhaseMetrics>
        {
            [PhaseNames.EncryptBallots] = new()
            {
                WallMs = wallMs, AllocatedBytes = allocated, Gc = new GcCounts(),
                BallotsProcessed = ballots, Aborted = aborted,
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
    public void Compare_ReportsNoBreachForIdenticalRuns()
    {
        var result = RunComparer.Compare(Record(), Record(), Default);

        Assert.True(result.Comparable);
        Assert.False(result.HasBreach);
        Assert.Empty(result.Warnings);
    }

    [Fact]
    public void Compare_FlagsAnAllocationRegressionAboveTolerance()
    {
        var result = RunComparer.Compare(
            Record(encryptAllocated: 1_000_000),
            Record(encryptAllocated: 1_100_000),
            Default);

        var delta = result.Deltas.Single(x => x.Phase == PhaseNames.EncryptBallots && x.Metric == "allocBytesPerBallot");
        Assert.True(delta.Breach);
        Assert.True(result.HasBreach);
        Assert.Equal(10, delta.PercentChange, precision: 3);
    }

    [Fact]
    public void Compare_ToleratesASmallTimingChange()
    {
        var result = RunComparer.Compare(Record(encryptWallMs: 1000), Record(encryptWallMs: 1100), Default);

        Assert.False(result.Deltas.Single(x => x.Metric == "msPerBallot").Breach);
    }

    [Fact]
    public void Compare_FlagsALargeTimingRegression()
    {
        var result = RunComparer.Compare(Record(encryptWallMs: 1000), Record(encryptWallMs: 2000), Default);

        Assert.True(result.Deltas.Single(x => x.Metric == "msPerBallot").Breach);
    }

    /// <summary>
    /// Regression guard: wall time is informational per the design ("strict on allocations, loose
    /// on wall time") -- it may be flagged as over tolerance, but it must never gate the exit code
    /// on its own. Allocations are held constant here so only the wall-time delta is at play.
    /// </summary>
    [Fact]
    public void Compare_LargeTimingOnlyRegressionIsFlaggedButDoesNotGateHasBreach()
    {
        var result = RunComparer.Compare(
            Record(encryptWallMs: 1000, encryptAllocated: 1_000_000),
            Record(encryptWallMs: 3000, encryptAllocated: 1_000_000),
            Default);

        var delta = result.Deltas.Single(x => x.Phase == PhaseNames.EncryptBallots && x.Metric == "msPerBallot");
        Assert.True(delta.Breach);
        Assert.False(delta.Gates);
        Assert.False(result.HasBreach);
    }

    [Fact]
    public void Compare_TreatsAnImprovementAsNoBreach()
    {
        var result = RunComparer.Compare(Record(encryptWallMs: 2000), Record(encryptWallMs: 1000), Default);

        Assert.False(result.HasBreach);
        Assert.True(result.Deltas.Single(x => x.Metric == "msPerBallot").PercentChange < 0);
    }

    [Fact]
    public void Compare_NormalizesByBallotsActuallyProcessed()
    {
        // Twice the work in twice the time is the same per-ballot cost.
        var result = RunComparer.Compare(
            Record(encryptWallMs: 1000, encryptAllocated: 1_000_000, ballots: 1000),
            Record(encryptWallMs: 2000, encryptAllocated: 2_000_000, ballots: 2000),
            Default);

        Assert.False(result.HasBreach);
    }

    [Fact]
    public void Compare_WarnsAboutPhasesPresentInOnlyOneRun()
    {
        var result = RunComparer.Compare(Record(), Record(includeDecrypt: true), Default);

        Assert.Contains(result.Warnings, x => x.Contains(PhaseNames.DecryptTally, StringComparison.Ordinal));
        Assert.DoesNotContain(result.Deltas, x => x.Phase == PhaseNames.DecryptTally);
    }

    [Fact]
    public void Compare_ExcludesAbortedPhasesFromBreachEvaluation()
    {
        var result = RunComparer.Compare(Record(), Record(encryptWallMs: 100_000, aborted: true), Default);

        Assert.False(result.HasBreach);
        Assert.Contains(result.Warnings, x => x.Contains("aborted", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("workstation", "Release", "sha256:same", "m1")]
    [InlineData("server", "Debug", "sha256:same", "m1")]
    [InlineData("server", "Release", "sha256:different", "m1")]
    [InlineData("server", "Release", "sha256:same", "m2")]
    public void Compare_RefusesToJudgeRunsFromDifferentConditions(
        string gcMode, string buildConfig, string configHash, string machineId)
    {
        var result = RunComparer.Compare(
            Record(),
            Record(encryptWallMs: 10_000, gcMode: gcMode, buildConfig: buildConfig,
                   configHash: configHash, machineId: machineId),
            Default);

        Assert.False(result.Comparable);
        Assert.False(result.HasBreach);
        Assert.NotEmpty(result.Warnings);
    }

    [Fact]
    public void Compare_ComparesPeakHeap()
    {
        var result = RunComparer.Compare(
            Record(peakHeapBytes: 1_000_000),
            Record(peakHeapBytes: 1_050_000),
            Default);

        var delta = result.Deltas.Single(x => x.Metric == "peakManagedHeapBytes");
        Assert.Equal(1_000_000, delta.Baseline);
        Assert.Equal(1_050_000, delta.Candidate);
        Assert.Equal(5, delta.PercentChange, precision: 3);
        Assert.False(delta.Gates);
        Assert.False(delta.Breach);
    }

    /// <summary>
    /// Peak heap is reported and flagged, but informational -- exactly like wall time. It was
    /// measured moving 8.63% between two identical back-to-back runs against a 10% tolerance:
    /// GC.GetTotalMemory(false) carries uncollected gen-0 garbage, and the sampler starts before
    /// DKG and warmup. Allocation moved ~0% in the same comparison, so it is the only gate.
    /// </summary>
    [Fact]
    public void Compare_FlagsAPeakHeapRegressionAboveToleranceButDoesNotGateTheExitCode()
    {
        var result = RunComparer.Compare(
            Record(peakHeapBytes: 1_000_000),
            Record(peakHeapBytes: 1_200_000),
            Default);

        var delta = result.Deltas.Single(x => x.Metric == "peakManagedHeapBytes");
        Assert.True(delta.Breach);
        Assert.False(delta.Gates);
        Assert.False(result.HasBreach);
    }

    /// <summary>
    /// ConfigHash cannot catch this: the scenario record it hashes holds the manifest as a path
    /// string, so editing the manifest file changes the election entirely while leaving ConfigHash
    /// byte-identical. ManifestHash is the only thing standing between that edit and a silently
    /// meaningless comparison.
    /// </summary>
    [Fact]
    public void Compare_RefusesToJudgeRunsWhoseManifestContentDiffers()
    {
        var result = RunComparer.Compare(
            Record(manifestHash: "sha256:one"),
            Record(encryptAllocated: 10_000_000, manifestHash: "sha256:two"),
            Default);

        Assert.False(result.Comparable);
        Assert.False(result.HasBreach);
        Assert.Contains(result.Warnings, x => x.Contains("Manifest", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// The concrete failure path Part 2 exists for: a run that threw during its first chunk records
    /// the encrypt phase with BallotsProcessed=0 and AllocatedBytes=0 (Part 1 now also marks that
    /// phase Aborted, but this test stands on Part 2 alone -- Correctness.Status is the general
    /// signal, independent of any one phase's Aborted flag). Appended as a baseline, that zero
    /// allocation used to hit the zero-baseline branch in RunComparer and declare a fabricated
    /// Breach on the gating allocation metric against any healthy candidate. Comparable must be
    /// false and HasBreach can never fire once it is.
    /// </summary>
    [Fact]
    public void Compare_RefusesToJudgeWhenTheBaselineErrored()
    {
        var result = RunComparer.Compare(
            Record(encryptAllocated: 0, correctnessStatus: CorrectnessStatus.Error),
            Record(encryptAllocated: 500),
            Default);

        Assert.False(result.Comparable);
        Assert.False(result.HasBreach);
        Assert.Contains(
            result.Warnings,
            x => x.Contains("did not complete successfully", StringComparison.OrdinalIgnoreCase)
                 && x.Contains("error", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Symmetric case with the candidate: a Failed correctness status (a run that completed and
    /// decrypted, but whose tally did not match the expected one) is just as untrustworthy a
    /// comparison target as Error, and must be refused the same way rather than reporting a
    /// spurious improvement or regression.
    /// </summary>
    [Fact]
    public void Compare_RefusesToJudgeWhenTheCandidateFailed()
    {
        var result = RunComparer.Compare(
            Record(),
            Record(encryptAllocated: 10_000_000, correctnessStatus: CorrectnessStatus.Failed),
            Default);

        Assert.False(result.Comparable);
        Assert.False(result.HasBreach);
        Assert.Contains(
            result.Warnings,
            x => x.Contains("did not complete successfully", StringComparison.OrdinalIgnoreCase)
                 && x.Contains("failed", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Compare_FlagsANewAllocationWhenBaselineAllocatedNothing()
    {
        // A phase that legitimately allocated zero at baseline and now allocates something is a
        // real regression on the strict metric, not noise -- it must not read as a flat 0.00%.
        var result = RunComparer.Compare(
            Record(encryptAllocated: 0),
            Record(encryptAllocated: 500),
            Default);

        var delta = result.Deltas.Single(x => x.Phase == PhaseNames.EncryptBallots && x.Metric == "allocBytesPerBallot");
        Assert.True(delta.BaselineWasZero);
        Assert.Equal(0, delta.PercentChange);
        Assert.True(delta.Breach);
        Assert.True(result.HasBreach);
    }
}
