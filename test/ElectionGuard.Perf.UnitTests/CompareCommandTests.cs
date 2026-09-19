using ElectionGuard.Perf.Cli;
using ElectionGuard.Perf.Cli.Commands;
using ElectionGuard.Perf.Cli.Configuration;
using ElectionGuard.Perf.Cli.Results;

namespace ElectionGuard.Perf.UnitTests;

/// <summary>
/// Integration coverage for `compare` -- the command whose exit code gates a build. Records are
/// seeded directly through RunRecordStore.Append (a real `run` is far too slow for a test), but each
/// record is shaped like a real one -- encrypt AND decrypt phases, matching environment/scenario
/// fields so RunComparer finds them comparable -- so RunComparer.Compare behaves exactly as it would
/// against a genuine results file. Thresholds come from the real committed perf/thresholds.json
/// (wallMsPercent 15, allocatedBytesPercent 2, peakHeapPercent 10) via --repo-root, so the tolerances
/// asserted against here are the tolerances actually enforced in production, not a test-local copy
/// that could drift from it.
///
/// Per-test temp directories only (never a shared results directory): RunRecordStore.Append has no
/// locking, and two writers racing the same file silently lose records.
/// </summary>
public class CompareCommandTests : IDisposable
{
    private const string MachineId = "egperf-compare-command-test";

    private static readonly string RepoRoot = RepoPaths.FindRoot(AppContext.BaseDirectory);

    private readonly string _directory = Directory.CreateTempSubdirectory("egperf-compare-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private static RunRecord Record(
        string runId,
        DateTimeOffset timestamp,
        double encryptWallMs = 1000,
        long encryptAllocated = 1_000_000,
        int ballots = 1000,
        string correctnessStatus = CorrectnessStatus.Passed) => new()
        {
            RunId = runId,
            TimestampUtc = timestamp,
            Scenario = new ScenarioInfo
            {
                Id = "compare-smoke", ConfigHash = "sha256:same", ManifestHash = "sha256:same",
                BallotCount = ballots, Seed = 1, GuardianN = 3, GuardianK = 2,
                Parallelism = 8, ChunkSize = 500,
            },
            Source = new SourceInfo { Commit = "abc123", Branch = "main", Dirty = false },
            Environment = new EnvironmentInfo
            {
                MachineId = MachineId, Cpu = "test-cpu", LogicalCores = 8, RamGb = 32,
                Os = "test-os", DotNet = "net9", GcMode = "server", BuildConfig = "Release",
            },
            Setup = new SetupInfo { DkgMs = 5 },
            Phases = new Dictionary<string, PhaseMetrics>
            {
                [PhaseNames.EncryptBallots] = new()
                {
                    WallMs = encryptWallMs, AllocatedBytes = encryptAllocated,
                    Gc = new GcCounts(), BallotsProcessed = ballots,
                },
                [PhaseNames.DecryptTally] = new()
                {
                    WallMs = encryptWallMs / 2, AllocatedBytes = encryptAllocated / 10,
                    Gc = new GcCounts(), BallotsProcessed = ballots,
                },
            },
            Derived = new DerivedMetrics
            {
                MsPerBallotEncrypt = encryptWallMs / ballots,
                BallotsPerSec = ballots * 1000.0 / encryptWallMs,
                AllocBytesPerBallot = encryptAllocated / (double)ballots,
            },
            Memory = new MemoryMetrics
            {
                PeakManagedHeapBytes = 5_000_000,
                PeakWorkingSetBytes = 10_000_000,
                TotalAllocatedBytes = encryptAllocated,
            },
            Correctness = new CorrectnessResult { Status = correctnessStatus },
        };

    /// <summary>Appends records to this test's own results file, in the order given.</summary>
    private void Seed(params RunRecord[] records)
    {
        var path = Path.Combine(_directory, $"{RunRecordStore.Slug(MachineId)}.jsonl");
        foreach (var record in records)
        {
            RunRecordStore.Append(path, record);
        }
    }

    private int Execute() => Program.Main(
    [
        "compare",
        "--results-dir", _directory,
        "--machine", MachineId,
        "--repo-root", RepoRoot,
    ]);

    /// <summary>Runs Execute with stdout captured, restoring Console.Out even if Execute throws.</summary>
    private (int ExitCode, string Output) ExecuteCapturingOutput()
    {
        var originalOut = Console.Out;
        var writer = new StringWriter();
        Console.SetOut(writer);
        try
        {
            return (Execute(), writer.ToString());
        }
        finally
        {
            Console.SetOut(originalOut);
        }
    }

    [Fact]
    public void Execute_ExitsZeroForACleanComparison()
    {
        Seed(
            Record("run-1", DateTimeOffset.UtcNow.AddMinutes(-10)),
            Record("run-2", DateTimeOffset.UtcNow));

        Assert.Equal(0, Execute());
    }

    /// <summary>
    /// Allocation is the sole gating metric: a candidate that allocates 10% more than baseline, well
    /// past the 2% tolerance, must fail the command. Wall time and DkgMs are held constant so this
    /// exercises the allocation gate alone.
    /// </summary>
    [Fact]
    public void Execute_ExitsOneWhenAllocationRegressesBeyondTolerance()
    {
        Seed(
            Record("run-1", DateTimeOffset.UtcNow.AddMinutes(-10), encryptAllocated: 1_000_000),
            Record("run-2", DateTimeOffset.UtcNow, encryptAllocated: 1_100_000));

        Assert.Equal(1, Execute());
    }

    /// <summary>
    /// Wall time is informational only. A +50% wall-time regression (well past the 15% tolerance)
    /// with allocation held exactly constant must still exit 0 -- but it must appear in the report
    /// as an over-tolerance line, not be silently dropped, and it must never be mislabeled REGRESSION
    /// (that label is reserved for a breach on the gating allocation metric).
    /// </summary>
    [Fact]
    public void Execute_ExitsZeroForAWallTimeOnlyRegressionButStillReportsIt()
    {
        Seed(
            Record("run-1", DateTimeOffset.UtcNow.AddMinutes(-10), encryptWallMs: 1000, encryptAllocated: 1_000_000),
            Record("run-2", DateTimeOffset.UtcNow, encryptWallMs: 1500, encryptAllocated: 1_000_000));

        var (exitCode, output) = ExecuteCapturingOutput();

        Assert.Equal(0, exitCode);
        Assert.Contains("OVER TOLERANCE", output);
        Assert.DoesNotContain("REGRESSION", output);
    }

    [Fact]
    public void Execute_ExitsTwoWhenFewerThanTwoRunsAreRecorded()
    {
        Seed(Record("run-1", DateTimeOffset.UtcNow));

        Assert.Equal(2, Execute());
    }

    [Fact]
    public void Execute_ExitsTwoWhenNoResultsFileExists()
    {
        // Deliberately unseeded: _directory exists but holds no <machine>.jsonl file at all.
        Assert.Equal(2, Execute());
    }
}
