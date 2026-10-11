using System.ComponentModel;
using System.Text.Json;
using ElectionGuard.Core.Models;
using ElectionGuard.Perf.Cli.Configuration;
using ElectionGuard.Testing.Common;
using Spectre.Console.Cli;

namespace ElectionGuard.Perf.Cli.Commands;

/// <summary>
/// Materializes a scenario's plaintext ballots to disk.
///
/// This is the cross-language fixture: encryptors written in other languages cannot call
/// BallotGenerator, so they consume these files instead. Because the corpus and an in-memory run
/// share a generator and a seed, they are provably the same workload -- which is what makes a
/// cross-language comparison meaningful.
///
/// Plaintext ballots are roughly 1 KB each, so a million-ballot corpus is about 1 GB. Do not commit
/// one; regenerate it from the seed.
/// </summary>
public sealed class CorpusCommand : Command<CorpusCommand.Settings>
{
    public sealed class Settings : PerfSettings
    {
        [CommandOption("--scenario <ID|PATH>", true)]
        [Description("A scenario id under perf/scenarios, or a path to a scenario file.")]
        public string Scenario { get; set; } = null!;

        [CommandOption("--output <DIR>", true)]
        [Description("Destination directory.")]
        public string Output { get; set; } = null!;

        [CommandOption("--ballots <N>")]
        [TypeConverter(typeof(WholeNumberConverter))]
        [Description("Override ballotCount.")]
        public int? Ballots { get; set; }

        [CommandOption("--seed <N>")]
        [TypeConverter(typeof(WholeNumberConverter))]
        [Description("Override seed.")]
        public int? Seed { get; set; }
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var root = settings.ResolveRepoRoot();

        var scenarioPath = File.Exists(settings.Scenario)
            ? settings.Scenario
            : Path.Combine(RepoPaths.Scenarios(root), $"{settings.Scenario}.json");

        var scenario = new ScenarioOverrides
        {
            BallotCount = settings.Ballots,
            Seed = settings.Seed,
        }.Apply(ScenarioLoader.Load(scenarioPath));

        var manifest = ManifestLoader.Load(root, scenario);

        Write(manifest, scenario, settings.Output);

        Console.WriteLine($"Wrote {scenario.BallotCount:N0} ballots to {settings.Output}");
        return 0;
    }

    public static void Write(Manifest manifest, PerfScenario scenario, string outputDirectory)
    {
        var ballotDirectory = Path.Combine(outputDirectory, "ballots");
        Directory.CreateDirectory(ballotDirectory);

        // Clean stale ballot files from a previous run. A non-.NET consumer globs this directory,
        // so orphaned files would be read into the corpus even if expected-tally.json is regenerated.
        // Only delete files that match our naming pattern (digits + .json) to safely narrow the scope.
        // The Length check is not redundant: a file named exactly ".json" has an empty basename, and
        // Enumerable.All is vacuously true on an empty sequence -- so without it, a file this tool
        // never wrote would be deleted. char.IsDigit accepts any Unicode decimal-digit category (e.g.
        // Arabic-indic digits), not just ASCII 0-9, so it is narrowed here to the exact character set
        // `{i}.json` (int.ToString()) ever produces.
        var staleFiles = Directory.GetFiles(ballotDirectory, "*.json")
            .Where(f => Path.GetFileNameWithoutExtension(f) is { Length: > 0 } name && name.All(c => c is >= '0' and <= '9'))
            .ToList();
        foreach (var staleFile in staleFiles)
        {
            File.Delete(staleFile);
        }
        if (staleFiles.Count > 0)
        {
            Console.WriteLine($"Removed {staleFiles.Count} stale ballot files.");
        }

        // The manifest file in Core's written form: the bytes H_B is computed over, so an encryptor
        // reading this corpus hashes what the harness hashes.
        File.WriteAllBytes(
            Path.Combine(outputDirectory, "manifest.json"),
            ElectionGuard.Core.Serialization.ManifestSerializer.Serialize(manifest));

        var generator = new BallotGenerator(manifest, scenario.Seed);
        var accumulator = new ExpectedTallyAccumulator(manifest);

        for (int i = 0; i < scenario.BallotCount; i++)
        {
            var ballot = generator.Generate(i);

            // Accumulate in the same order as the in-memory runner for consistency, though nothing
            // in this path mutates the ballot (unlike the runner, which may modify overvoted ballots
            // during encryption). The ordering ensures the two approaches remain synchronized.
            accumulator.Add(ballot);

            File.WriteAllBytes(
                Path.Combine(ballotDirectory, $"{i}.json"),
                JsonSerializer.SerializeToUtf8Bytes(ballot, PerfJson.Options));
        }

        var document = ExpectedTallyDocument.From(accumulator.Build());

        File.WriteAllBytes(
            Path.Combine(outputDirectory, "expected-tally.json"),
            JsonSerializer.SerializeToUtf8Bytes(document, PerfJson.Options));
    }
}
