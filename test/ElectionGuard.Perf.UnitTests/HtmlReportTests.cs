using ElectionGuard.Perf.Cli.Configuration;
using ElectionGuard.Perf.Cli.Reporting;
using ElectionGuard.Perf.Cli.Results;

namespace ElectionGuard.Perf.UnitTests;

public class HtmlReportTests
{
    private static RunRecord Record(string scenarioId, string commit, double msPerBallot) => new()
    {
        RunId = commit,
        TimestampUtc = DateTimeOffset.UtcNow,
        Scenario = new ScenarioInfo
        {
            Id = scenarioId, ConfigHash = "sha256:c", ManifestHash = "sha256:m",
            BallotCount = 1000, Seed = 1, GuardianN = 3, GuardianK = 2, Parallelism = 8, ChunkSize = 500,
        },
        Source = new SourceInfo { Commit = commit, Branch = "main", Dirty = false },
        Environment = new EnvironmentInfo
        {
            MachineId = "m1", Cpu = "cpu", LogicalCores = 8, RamGb = 32,
            Os = "os", DotNet = "net9", GcMode = "server", BuildConfig = "Release",
        },
        Setup = new SetupInfo { DkgMs = 1 },
        Phases = new Dictionary<string, PhaseMetrics>
        {
            [PhaseNames.EncryptBallots] = new()
            {
                WallMs = msPerBallot * 1000, AllocatedBytes = 1000,
                Gc = new GcCounts(), BallotsProcessed = 1000,
            },
        },
        Derived = new DerivedMetrics { MsPerBallotEncrypt = msPerBallot, BallotsPerSec = 1, AllocBytesPerBallot = 1 },
        Memory = new MemoryMetrics { PeakManagedHeapBytes = 1, PeakWorkingSetBytes = 1, TotalAllocatedBytes = 1 },
        Correctness = new CorrectnessResult { Status = CorrectnessStatus.Passed },
    };

    [Fact]
    public void Render_ProducesSelfContainedHtml()
    {
        var html = HtmlReport.Render([Record("medium", "aaa", 4.0), Record("medium", "bbb", 3.5)]);

        Assert.StartsWith("<!doctype html>", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("</html>", html);

        // Together, these are what "self-contained" means operationally: no inline <script> in any
        // form, no <link> stylesheet, no CSS url()/@import, no src= attribute, and no scheme-based
        // reference (://, which also catches protocol-relative http:// and https://). Do not prune
        // this list back to just "http://"/"https://"/"<script src=" -- that narrower check misses a
        // bare <script>...</script>, a <link rel="stylesheet">, a protocol-relative //cdn/x.css, and
        // a CSS url(...)/@import, all of which would just as surely break "opens from disk today and
        // publishes to GitHub Pages unmodified".
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<link", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("url(", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("@import", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("src=", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("://", html, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Render_SectionsBySpecificScenario()
    {
        var html = HtmlReport.Render([Record("medium", "aaa", 4.0), Record("large", "bbb", 9.0)]);

        // Pinned to the section heading, not a bare Contains: a report that merely mentioned the
        // scenario id in a table cell without sectioning by it would satisfy a looser assertion.
        Assert.Contains("<h2>medium</h2>", html);
        Assert.Contains("<h2>large</h2>", html);
    }

    [Fact]
    public void Render_PlotsAPointPerRun()
    {
        var html = HtmlReport.Render([Record("medium", "aaa", 4.0), Record("medium", "bbb", 3.5), Record("medium", "ccc", 3.0)]);

        // Assert the actual claim -- one plotted point per run -- rather than a fixed relationship
        // between circle count and chart count. Counting <circle> elements and dividing by "the
        // number of charts per scenario" is coupled to that count: a legitimate third chart added
        // later breaks this via integer truncation even though per-run plotting stayed correct.
        // Extracting the first <polyline>'s own points instead is independent of how many charts exist.
        var polyline = System.Text.RegularExpressions.Regex.Match(html, "<polyline[^>]*points=\"([^\"]*)\"");
        Assert.True(polyline.Success, "Expected at least one <polyline> with a points attribute.");

        var points = polyline.Groups[1].Value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(3, points.Length);
    }

    [Fact]
    public void Render_EscapesRecordText()
    {
        const string scenarioPayload = "<script>alert(1)</script>";
        const string commitPayload = "<img src=x onerror=alert(2)>";

        var html = HtmlReport.Render([Record(scenarioPayload, commitPayload, 1.0)]);

        Assert.DoesNotContain(scenarioPayload, html);
        Assert.Contains("&lt;script&gt;", html);

        // The commit sha reaches two injection sites: the results table cell, and the SVG <title>
        // tooltip on each plotted point. Only the scenario id (which surfaces solely in <h2>) was
        // covered before this test was extended -- the <title> tooltip had no coverage at all.
        Assert.DoesNotContain(commitPayload, html);
        Assert.Contains("&lt;img", html);

        // The document's own <head><title> is the first match; the SVG tooltip on the plotted point
        // is the second -- target that one specifically rather than the page title.
        var titles = System.Text.RegularExpressions.Regex.Matches(html, "<title>(.*?)</title>");
        Assert.True(titles.Count >= 2, "Expected the page <title> plus at least one SVG <title> tooltip.");
        var tooltip = titles[1].Value;
        Assert.DoesNotContain(commitPayload, tooltip);
        Assert.Contains("&lt;img", tooltip);
    }

    /// <summary>
    /// Render sorts WITHIN each scenario's own section, but used to trust the caller's ordering for
    /// the top-of-page "most recent" headline, reading records[^1] directly. ReportCommand happens
    /// to sort its list before calling Render, but nothing at this boundary enforced that -- a
    /// caller passing an unsorted list got a wrong headline timestamp with no error. Passing the
    /// newer record FIRST here reproduces exactly the ordering that would fool records[^1].
    /// </summary>
    [Fact]
    public void Render_ReportsTheActualMostRecentRunRegardlessOfInputOrder()
    {
        var older = Record("medium", "aaa", 4.0) with
        {
            TimestampUtc = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
        };
        var newer = Record("medium", "bbb", 3.5) with
        {
            TimestampUtc = new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero),
        };

        var html = HtmlReport.Render([newer, older]);

        Assert.Contains(newer.TimestampUtc.ToString("u"), html);
        Assert.DoesNotContain(older.TimestampUtc.ToString("u"), html);
    }

    /// <summary>
    /// The report used to chart and tabulate only the encrypt phase, silently dropping every other
    /// phase, the DKG setup time, memory, serialization, and notes the run had recorded.
    /// </summary>
    [Fact]
    public void Render_IncludesEveryRecordedPhaseAndMetric()
    {
        var record = Record("medium", "aaa", 4.0) with
        {
            Setup = new SetupInfo { DkgMs = 2047 },
            Phases = new Dictionary<string, PhaseMetrics>
            {
                [PhaseNames.EncryptBallots] = Phase(4000),
                [PhaseNames.VerifyBallots] = Phase(3000),
                [PhaseNames.Tally] = Phase(474),
                [PhaseNames.VerifyTally] = Phase(477),
                [PhaseNames.DecryptTally] = Phase(1609) with { Aborted = true, BallotsProcessed = 10 },
                [PhaseNames.VerifyDecryption] = Phase(55),
                [PhaseNames.WriteRecord] = Phase(191),
                [PhaseNames.VerifyRecord] = Phase(1250),
            },
            Memory = new MemoryMetrics
            {
                PeakManagedHeapBytes = 28544008, PeakWorkingSetBytes = 83943424, TotalAllocatedBytes = 344196088,
            },
            Serialization = new SerializationMetrics
            {
                Json = new SerializerMetrics { SerializeOpsPerSec = 1340, DeserializeOpsPerSec = 1384, Bytes = 16310 },
                Protobuf = new SerializerMetrics { SerializeOpsPerSec = 55601, DeserializeOpsPerSec = 38741, Bytes = 9709 },
            },
            Correctness = new CorrectnessResult
            {
                Status = CorrectnessStatus.Failed,
                Mismatches = [new TallyMismatch { ContestId = "contest-1", ChoiceId = "choice-2", Expected = 5, Actual = 6 }],
            },
            Notes = new Dictionary<string, string> { ["tallyVerification"] = "ran" },
        };

        var html = HtmlReport.Render([record]);

        foreach (var phase in PhaseNames.All)
        {
            Assert.Contains($"<h3>{phase}: milliseconds per ballot</h3>", html);
            Assert.Contains($"<th>{phase} ms/ballot</th>", html);
        }

        Assert.Contains("2,047 ms", html);
        Assert.Contains("27.2", html);   // peak heap MB
        Assert.Contains("80.1", html);   // peak working set MB
        Assert.Contains("328.3", html);  // total allocated MB
        Assert.Contains("16,310", html);
        Assert.Contains("55,601", html);
        Assert.Contains("aborted", html);
        Assert.Contains("contest-1", html);
        Assert.Contains("choice-2", html);
        Assert.Contains("tallyVerification: ran", html);
        Assert.Contains("sha256:m", html);
    }

    [Fact]
    public void Render_OmitsPhasesNoRunRecorded()
    {
        var html = HtmlReport.Render([Record("medium", "aaa", 4.0)]);

        Assert.DoesNotContain($"{PhaseNames.DecryptTally} ms/ballot", html);
        Assert.DoesNotContain($"{PhaseNames.VerifyTally}: milliseconds per ballot", html);
    }

    private static PhaseMetrics Phase(double wallMs) => new()
    {
        WallMs = wallMs, AllocatedBytes = 1000, Gc = new GcCounts { G0 = 1 }, BallotsProcessed = 1000,
    };

    [Fact]
    public void Render_HandlesAnEmptyHistory()
    {
        var html = HtmlReport.Render([]);

        Assert.Contains("No runs recorded", html);
    }
}
