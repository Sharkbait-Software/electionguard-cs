using ElectionGuard.Perf.Cli;
using ElectionGuard.Perf.Cli.Commands;
using ElectionGuard.Perf.Cli.Configuration;
using ElectionGuard.Perf.Cli.Results;

namespace ElectionGuard.Perf.UnitTests;

/// <summary>
/// Integration coverage for `report`: this is the path that actually writes the HTML file a user
/// opens, so it is not enough that HtmlReport.Render (see HtmlReportTests) produces good markup --
/// ReportCommand.Execute has to find the seeded records, write them to the requested --output path,
/// and create any missing parent directory along the way.
///
/// Per-test temp directories only (never a shared results directory): RunRecordStore.Append has no
/// locking, and two writers racing the same file silently lose records.
/// </summary>
public class ReportCommandTests : IDisposable
{
    private static readonly string RepoRoot = RepoPaths.FindRoot(AppContext.BaseDirectory);

    private readonly string _directory = Directory.CreateTempSubdirectory("egperf-report-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private static RunRecord Record(string scenarioId, string runId, double encryptWallMs) => new()
    {
        RunId = runId,
        TimestampUtc = DateTimeOffset.UtcNow,
        Scenario = new ScenarioInfo
        {
            Id = scenarioId, ConfigHash = "sha256:c", ManifestHash = "sha256:m",
            BallotCount = 1000, Seed = 1, GuardianN = 3, GuardianK = 2, Parallelism = 8, ChunkSize = 500,
        },
        Source = new SourceInfo { Commit = runId, Branch = "main", Dirty = false },
        Environment = new EnvironmentInfo
        {
            MachineId = "egperf-report-command-test", Cpu = "test-cpu", LogicalCores = 8, RamGb = 32,
            Os = "test-os", DotNet = "net9", GcMode = "server", BuildConfig = "Release",
        },
        Setup = new SetupInfo { DkgMs = 5 },
        Phases = new Dictionary<string, PhaseMetrics>
        {
            [PhaseNames.EncryptBallots] = new()
            {
                WallMs = encryptWallMs, AllocatedBytes = 1000,
                Gc = new GcCounts(), BallotsProcessed = 1000,
            },
        },
        Derived = new DerivedMetrics
        {
            MsPerBallotEncrypt = encryptWallMs / 1000, BallotsPerSec = 1, AllocBytesPerBallot = 1,
        },
        Memory = new MemoryMetrics { PeakManagedHeapBytes = 1, PeakWorkingSetBytes = 1, TotalAllocatedBytes = 1 },
        Correctness = new CorrectnessResult { Status = CorrectnessStatus.Passed },
    };

    [Fact]
    public void Execute_WritesASelfContainedHtmlReportContainingTheSeededScenario()
    {
        var resultsDirectory = Path.Combine(_directory, "results");
        var path = Path.Combine(resultsDirectory, "egperf-report-command-test.jsonl");
        RunRecordStore.Append(path, Record("report-smoke", "run-1", 32));
        RunRecordStore.Append(path, Record("report-smoke", "run-2", 30));

        // The output path lives under a directory that does not exist yet -- ReportCommand must
        // create it, exactly as it would for a user's first `--output some/new/path/report.html`.
        var output = Path.Combine(_directory, "out", "report.html");

        var exitCode = Program.Main(
        [
            "report",
            "--results-dir", resultsDirectory,
            "--output", output,
            "--repo-root", RepoRoot,
        ]);

        Assert.Equal(0, exitCode);
        Assert.True(File.Exists(output));

        var html = File.ReadAllText(output);

        // Parses as a complete document.
        Assert.StartsWith("<!doctype html>", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("</html>", html);

        // A section for the seeded scenario.
        Assert.Contains("<h2>report-smoke</h2>", html);

        // Self-containment, mirroring HtmlReportTests.Render_ProducesSelfContainedHtml: this is the
        // path that actually writes the file a user opens from disk or publishes unmodified, so the
        // property must hold end to end, not just in HtmlReport.Render's own unit test.
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<link", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("url(", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("@import", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("src=", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("://", html, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A bare filename with no directory component (`--output report.html`) used to throw
    /// ArgumentException: Path.GetDirectoryName("report.html") returns "", and
    /// Directory.CreateDirectory("") is not the no-op it looks like -- it throws. Program.cs
    /// catches ArgumentException and exits 2, so this degraded to an unfriendly message rather than
    /// a crash, but `--output report.html` is a perfectly reasonable thing to type (write it next to
    /// wherever the command is run from) and must work.
    /// </summary>
    [Fact]
    public void Execute_AcceptsABareRelativeOutputFilenameWithNoDirectoryComponent()
    {
        var resultsDirectory = Path.Combine(_directory, "results");
        RunRecordStore.Append(
            Path.Combine(resultsDirectory, "egperf-report-command-test.jsonl"),
            Record("report-smoke", "run-1", 32));

        var previousDirectory = Environment.CurrentDirectory;
        var workingDirectory = Directory.CreateTempSubdirectory("egperf-report-cwd-").FullName;
        Environment.CurrentDirectory = workingDirectory;
        try
        {
            var exitCode = Program.Main(
            [
                "report",
                "--results-dir", resultsDirectory,
                "--output", "report.html",
                "--repo-root", RepoRoot,
            ]);

            Assert.Equal(0, exitCode);
            Assert.True(File.Exists(Path.Combine(workingDirectory, "report.html")));
        }
        finally
        {
            Environment.CurrentDirectory = previousDirectory;
            Directory.Delete(workingDirectory, recursive: true);
        }
    }

    [Fact]
    public void Execute_DefaultsTheOutputPathToReportHtmlUnderTheResultsDirectory()
    {
        var resultsDirectory = Path.Combine(_directory, "results");
        RunRecordStore.Append(
            Path.Combine(resultsDirectory, "egperf-report-command-test.jsonl"),
            Record("report-smoke", "run-1", 32));

        var exitCode = Program.Main(
        [
            "report",
            "--results-dir", resultsDirectory,
            "--repo-root", RepoRoot,
        ]);

        Assert.Equal(0, exitCode);
        Assert.True(File.Exists(Path.Combine(resultsDirectory, "report.html")));
    }
}
