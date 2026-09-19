using System.Text.Json;
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Perf.Cli;
using ElectionGuard.Perf.Cli.Commands;
using ElectionGuard.Perf.Cli.Configuration;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Perf.UnitTests;

public class CorpusCommandTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("egperf-corpus-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private static PerfScenario Scenario(int ballotCount) => new()
    {
        Id = "corpus-test",
        Manifest = "unused.json",
        BallotCount = ballotCount,
        Seed = 777,
    };

    [Fact]
    public void Write_ProducesOneFilePerBallotPlusManifestAndTally()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();

        CorpusCommand.Write(manifest, Scenario(5), _directory);

        Assert.Equal(5, Directory.GetFiles(Path.Combine(_directory, "ballots")).Length);
        Assert.True(File.Exists(Path.Combine(_directory, "manifest.json")));
        Assert.True(File.Exists(Path.Combine(_directory, "expected-tally.json")));
    }

    [Fact]
    public void Write_ProducesTheSameBallotsAsTheInMemoryGenerator()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var scenario = Scenario(3);

        CorpusCommand.Write(manifest, scenario, _directory);

        var generator = new BallotGenerator(manifest, scenario.Seed);
        for (int i = 0; i < 3; i++)
        {
            var onDisk = JsonSerializer.Deserialize<Ballot>(
                File.ReadAllBytes(Path.Combine(_directory, "ballots", $"{i}.json")), PerfJson.Options)!;
            var inMemory = generator.Generate(i);

            Assert.Equal(inMemory.BallotStyleId, onDisk.BallotStyleId);
            Assert.Equal(
                inMemory.Contests.SelectMany(c => c.Choices).Select(c => c.SelectionValue),
                onDisk.Contests.SelectMany(c => c.Choices).Select(c => c.SelectionValue));
        }
    }

    [Fact]
    public void Write_RecordsAnExpectedTallyMatchingTheGeneratedBallots()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var scenario = Scenario(50);

        CorpusCommand.Write(manifest, scenario, _directory);

        var written = JsonSerializer.Deserialize<ExpectedTallyDocument>(
            File.ReadAllBytes(Path.Combine(_directory, "expected-tally.json")), PerfJson.Options)!;

        var accumulator = new ExpectedTallyAccumulator(manifest);
        var generator = new BallotGenerator(manifest, scenario.Seed);
        for (int i = 0; i < 50; i++)
        {
            accumulator.Add(generator.Generate(i));
        }

        var expected = accumulator.Build();
        foreach (var contestId in expected.ContestIds)
        {
            var writtenContest = written.Contests[contestId];
            var expectedCounters = expected.GetCounters(contestId);

            Assert.Equal(expectedCounters.Overvotes, writtenContest.Overvotes);
            Assert.Equal(expectedCounters.Nullvotes, writtenContest.Nullvotes);
            Assert.Equal(expectedCounters.Undervotes, writtenContest.Undervotes);
            Assert.Equal(expectedCounters.WriteIns, writtenContest.WriteIns);

            foreach (var choiceId in expected.ChoiceIds(contestId))
            {
                Assert.Equal(expected.GetVotes(contestId, choiceId), writtenContest.Choices[choiceId]);
            }
        }
    }

    [Fact]
    public void Write_RemovesStaleBallotsWhenWritingASmallerCorpusToTheSameDirectory()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();

        // Write a larger corpus first
        CorpusCommand.Write(manifest, Scenario(10), _directory);
        Assert.Equal(10, Directory.GetFiles(Path.Combine(_directory, "ballots")).Length);

        // Write a smaller corpus to the same directory
        CorpusCommand.Write(manifest, Scenario(3), _directory);

        // Verify only the new ballots remain
        var ballotFiles = Directory.GetFiles(Path.Combine(_directory, "ballots"));
        Assert.Equal(3, ballotFiles.Length);

        // Verify stale files don't exist
        for (int i = 3; i < 10; i++)
        {
            Assert.False(File.Exists(Path.Combine(_directory, "ballots", $"{i}.json")),
                $"Stale file {i}.json should have been removed");
        }
    }

    /// <summary>
    /// Every test above drives CorpusCommand.Write directly -- the unit-level helper that does the
    /// actual file writing. This one drives CorpusCommand.Execute, the real command class: it resolves
    /// the repo root, loads the committed "smoke" scenario file and the manifest it points at, applies
    /// the --ballots/--seed overrides, and only THEN calls Write. That resolution chain
    /// (RepoPaths.FindRoot -> ScenarioLoader.Load -> ScenarioOverrides.Apply -> ManifestLoader.Load) is
    /// exactly what the other tests in this file cannot exercise, and is untested without this. The
    /// scenario's default ballotCount (1000) is overridden down to 5 so this stays fast -- corpus
    /// generation does no cryptography, so even that override is only for speed, not correctness.
    /// </summary>
    [Fact]
    public void Execute_WritesACorpusFromARealScenarioAndManifest()
    {
        var repoRoot = RepoPaths.FindRoot(AppContext.BaseDirectory);
        var output = Path.Combine(_directory, "out");

        var exitCode = Program.Main(
        [
            "corpus",
            "--scenario", "smoke",
            "--ballots", "5",
            "--seed", "777",
            "--output", output,
            "--repo-root", repoRoot,
        ]);

        Assert.Equal(0, exitCode);
        Assert.True(File.Exists(Path.Combine(output, "manifest.json")));
        Assert.Equal(5, Directory.GetFiles(Path.Combine(output, "ballots")).Length);
        Assert.True(File.Exists(Path.Combine(output, "expected-tally.json")));

        // The expected tally is in the canonical schema: contests keyed by id, each carrying the
        // per-contest counters plus a choices map -- see ExpectedTallyDocument's own doc comment.
        var tally = JsonSerializer.Deserialize<ExpectedTallyDocument>(
            File.ReadAllBytes(Path.Combine(output, "expected-tally.json")), PerfJson.Options)!;

        Assert.NotEmpty(tally.Contests);
        foreach (var contest in tally.Contests.Values)
        {
            Assert.True(contest.Overvotes >= 0);
            Assert.True(contest.Nullvotes >= 0);
            Assert.True(contest.Undervotes >= 0);
            Assert.True(contest.WriteIns >= 0);
            Assert.NotEmpty(contest.Choices);
        }
    }

    /// <summary>
    /// The stale-file filter matches only ASCII 0-9 (see CorpusCommand.Write), not char.IsDigit's
    /// broader Unicode decimal-digit category. A file named with an Arabic-indic digit is not
    /// something this tool would ever write as a ballot file, so it must survive the cleanup pass.
    /// </summary>
    [Fact]
    public void Write_DoesNotTreatANonAsciiDigitNamedFileAsStale()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();

        CorpusCommand.Write(manifest, Scenario(3), _directory);

        var ballotDirectory = Path.Combine(_directory, "ballots");
        var nonAsciiDigitFile = Path.Combine(ballotDirectory, "١.json"); // Arabic-Indic digit one
        File.WriteAllText(nonAsciiDigitFile, "not a ballot");

        CorpusCommand.Write(manifest, Scenario(3), _directory);

        Assert.True(File.Exists(nonAsciiDigitFile),
            "A file named with a Unicode (non-ASCII) digit was deleted by the stale-file filter.");
    }

    /// <summary>--scenario also accepts a literal path, not just a name resolved under perf/scenarios.</summary>
    [Fact]
    public void Execute_AcceptsAScenarioArgumentThatIsALiteralFilePath()
    {
        var repoRoot = RepoPaths.FindRoot(AppContext.BaseDirectory);
        var scenarioPath = Path.Combine(RepoPaths.Scenarios(repoRoot), "smoke.json");
        var output = Path.Combine(_directory, "out");

        var exitCode = Program.Main(
        [
            "corpus",
            "--scenario", scenarioPath,
            "--ballots", "3",
            "--output", output,
            "--repo-root", repoRoot,
        ]);

        Assert.Equal(0, exitCode);
        Assert.Equal(3, Directory.GetFiles(Path.Combine(output, "ballots")).Length);
    }
}
