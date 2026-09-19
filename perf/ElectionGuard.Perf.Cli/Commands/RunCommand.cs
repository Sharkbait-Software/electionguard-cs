using System.ComponentModel;
using ElectionGuard.Core.Models;
using ElectionGuard.Perf.Cli.Configuration;
using ElectionGuard.Perf.Cli.Reporting;
using ElectionGuard.Perf.Cli.Results;
using ElectionGuard.Perf.Cli.Running;
using Spectre.Console.Cli;

namespace ElectionGuard.Perf.Cli.Commands;

public sealed class RunCommand : Command<RunCommand.Settings>
{
    public sealed class Settings : PerfSettings
    {
        [CommandOption("--scenario <ID|PATH>", true)]
        [Description("A scenario id under perf/scenarios, or a path to a scenario file.")]
        public string Scenario { get; set; } = null!;

        [CommandOption("--ballots <N>")]
        [TypeConverter(typeof(WholeNumberConverter))]
        [Description("Override ballotCount.")]
        public int? Ballots { get; set; }

        [CommandOption("--seed <N>")]
        [TypeConverter(typeof(WholeNumberConverter))]
        [Description("Override seed.")]
        public int? Seed { get; set; }

        [CommandOption("--parallelism <N>")]
        [TypeConverter(typeof(WholeNumberConverter))]
        [Description("Override parallelism (0 = all cores, 1 = serial baseline).")]
        public int? Parallelism { get; set; }

        [CommandOption("--chunk <N>")]
        [TypeConverter(typeof(WholeNumberConverter))]
        [Description("Override chunkSize.")]
        public int? Chunk { get; set; }

        [CommandOption("--warmup <N>")]
        [TypeConverter(typeof(WholeNumberConverter))]
        [Description("Override warmupBallots.")]
        public int? Warmup { get; set; }

        [CommandOption("--guardians <N:K>")]
        [Description("Override the guardian threshold.")]
        public GuardianThreshold? Guardians { get; set; }

        [CommandOption("--no-decrypt")]
        [Description("Skip the decrypt phase.")]
        public bool NoDecrypt { get; set; }

        [CommandOption("--no-ballot-verification")]
        [Description("Skip Verifications 5-8.")]
        public bool NoBallotVerification { get; set; }

        [CommandOption("--no-tally-verification")]
        [Description("Skip Verification 9.")]
        public bool NoTallyVerification { get; set; }

        [CommandOption("--no-serialization")]
        [Description("Skip the serialization sub-benchmark.")]
        public bool NoSerialization { get; set; }

        [CommandOption("--repeat <N>")]
        [TypeConverter(typeof(WholeNumberConverter))]
        [Description("Run N times, sharing a repeat group.")]
        public int? Repeat { get; set; }

        [CommandOption("--machine <ID>")]
        [Description("Override the machine id (defaults to the hostname).")]
        public string? Machine { get; set; }

        [CommandOption("--markdown")]
        [Description("Render the summary as a markdown table.")]
        public bool Markdown { get; set; }

        [CommandOption("--results-dir <DIR>")]
        [Description("Override perf/results.")]
        public string? ResultsDir { get; set; }

        [CommandOption("--allow-debug")]
        [Description("Record a result from a Debug build.")]
        public bool AllowDebug { get; set; }
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var root = settings.ResolveRepoRoot();

        if (EnvironmentProbe.IsDebug && !settings.AllowDebug)
        {
            Console.Error.WriteLine(
                "Refusing to record a Debug-build result. Rebuild with -c Release, or pass --allow-debug " +
                "to record it anyway (the record will say Debug, and compare will refuse to weigh it " +
                "against a Release run).");
            return 2;
        }

        var scenarioPath = File.Exists(settings.Scenario)
            ? settings.Scenario
            : Path.Combine(RepoPaths.Scenarios(root), $"{settings.Scenario}.json");

        var scenario = new ScenarioOverrides
        {
            BallotCount = settings.Ballots,
            Seed = settings.Seed,
            Parallelism = settings.Parallelism,
            ChunkSize = settings.Chunk,
            WarmupBallots = settings.Warmup,
            GuardianN = settings.Guardians?.N,
            GuardianK = settings.Guardians?.K,
            BallotVerification = settings.NoBallotVerification ? false : null,
            TallyVerification = settings.NoTallyVerification ? false : null,
            Decrypt = settings.NoDecrypt ? false : null,
            Serialization = settings.NoSerialization ? false : null,
        }.Apply(ScenarioLoader.Load(scenarioPath));

        var manifestPath = ManifestLoader.ResolvePath(root, scenario);
        var manifest = ManifestLoader.Load(root, scenario);

        int repeat = settings.Repeat ?? 1;
        string? repeatGroup = repeat > 1 ? Guid.NewGuid().ToString("n")[..8] : null;
        int exitCode = 0;

        for (int iteration = 0; iteration < repeat; iteration++)
        {
            var record = RunOnce(root, settings, scenario, manifest, manifestPath, repeatGroup);
            Console.WriteLine(ConsoleReport.Render(record, settings.Markdown));

            // Failed means the tally was wrong; Error means the run threw. Both are recorded, and
            // both must fail the command -- before Error existed the exception simply escaped.
            if (record.Correctness.Status is CorrectnessStatus.Failed or CorrectnessStatus.Error)
            {
                exitCode = 1;
            }
        }

        return exitCode;
    }

    private static RunRecord RunOnce(
        string root,
        Settings settings,
        PerfScenario scenario,
        Manifest manifest,
        string manifestPath,
        string? repeatGroup)
    {
        Console.WriteLine($"Running scenario '{scenario.Id}' ({scenario.BallotCount:N0} ballots)...");

        var outcome = new ScenarioRunner(scenario, manifest, Console.WriteLine).Run();

        // A setup-time failure (DKG, encryption-record construction, warmup) is caught inside
        // ScenarioRunner.Run and returned as a PARTIAL outcome with an EMPTY Phases dictionary --
        // none of Stage 1 ever ran, so there is no Encrypt phase to index. Indexing it unconditionally
        // used to turn that outcome into a KeyNotFoundException here, defeating the whole point of
        // catching the setup failure in the first place: the run still died, just later and with a
        // less informative exception. Derive what is available (nothing, in that case) instead.
        outcome.Phases.TryGetValue(PhaseNames.EncryptBallots, out var encryptPhase);
        int encrypted = encryptPhase is not null ? Math.Max(1, encryptPhase.BallotsProcessed) : 0;

        var derived = encryptPhase is not null
            ? new DerivedMetrics
            {
                MsPerBallotEncrypt = encryptPhase.WallMs / encrypted,
                BallotsPerSec = encryptPhase.WallMs > 0 ? encrypted * 1000.0 / encryptPhase.WallMs : 0,
                AllocBytesPerBallot = encryptPhase.AllocatedBytes / (double)encrypted,
            }
            : new DerivedMetrics { MsPerBallotEncrypt = 0, BallotsPerSec = 0, AllocBytesPerBallot = 0 };

        var record = new RunRecord
        {
            RunId = $"{DateTime.UtcNow:yyyyMMdd'T'HHmmss'Z'}-{Guid.NewGuid().ToString("n")[..6]}",
            TimestampUtc = DateTimeOffset.UtcNow,
            RepeatGroup = repeatGroup,
            Scenario = new ScenarioInfo
            {
                Id = scenario.Id,
                ConfigHash = ScenarioLoader.ComputeConfigHash(scenario),
                ManifestHash = ManifestHasher.Hash(manifest),
                BallotCount = scenario.BallotCount,
                Seed = scenario.Seed,
                GuardianN = scenario.Guardians.N,
                GuardianK = scenario.Guardians.K,
                Parallelism = scenario.Parallelism == 0 ? Environment.ProcessorCount : scenario.Parallelism,
                ChunkSize = scenario.ChunkSize,
            },
            Source = GitProbe.Capture(root),
            Environment = EnvironmentProbe.Capture(settings.Machine),
            Setup = new SetupInfo { DkgMs = outcome.DkgMs },
            Phases = outcome.Phases,
            Derived = derived,
            Memory = outcome.Memory,
            Serialization = scenario.Phases.Serialization && outcome.RepresentativeBallot is not null
                ? SerializationBenchmark.Measure(outcome.RepresentativeBallot)
                : null,
            Correctness = outcome.Correctness,
            Notes = outcome.Notes,
        };

        record.Notes["manifest"] = Path.GetRelativePath(root, manifestPath).Replace('\\', '/');

        var resultsDirectory = settings.ResultsDir ?? RepoPaths.Results(root);
        RunRecordStore.Append(
            Path.Combine(resultsDirectory, $"{record.Environment.MachineId}.jsonl"),
            record);
        RunRecordStore.WriteLatest(Path.Combine(resultsDirectory, "latest"), record);

        return record;
    }
}
