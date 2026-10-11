using System.Text.Json.Serialization;

namespace ElectionGuard.Perf.Cli.Configuration;

/// <summary>
/// A single measurable workload. Everything that changes what is measured lives here, so that a
/// scenario which is impractical today becomes practical by editing JSON rather than code.
/// </summary>
public sealed record PerfScenario
{
    public required string Id { get; init; }

    /// <summary>Repo-relative path to the manifest defining the election shape.</summary>
    public required string Manifest { get; init; }

    public required int BallotCount { get; init; }

    public int Seed { get; init; } = 1;

    public GuardianThreshold Guardians { get; init; } = new();

    /// <summary>Degree of parallelism for encryption. 0 means Environment.ProcessorCount.</summary>
    public int Parallelism { get; init; }

    /// <summary>
    /// Ballots generated, encrypted and aggregated before being discarded. Bounds peak memory:
    /// encrypted ballots are roughly 50 KB each for a four-contest manifest, so a wide manifest
    /// needs a smaller chunk.
    /// </summary>
    public int ChunkSize { get; init; } = 5000;

    public int WarmupBallots { get; init; } = 200;

    public PhaseSettings Phases { get; init; } = new();

    /// <summary>
    /// Per-phase wall-clock budget in minutes, keyed by <see cref="PhaseNames"/>. A phase that
    /// exceeds its budget stops at the next chunk boundary and is recorded as aborted rather than
    /// hanging the run. An absent key means unlimited.
    /// </summary>
    public Dictionary<string, double> Budgets { get; init; } = new();

    /// <summary>
    /// How the election record is written when <see cref="PhaseSettings.WriteRecord"/> is on (design
    /// §8.5). Null takes the defaults (one device, protobuf, a directory). Left out of the config
    /// hash when null, so scenarios that write no record keep the hash they had before it existed.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public RecordSettings? Record { get; init; }
}

/// <summary>The election record the <c>WriteRecord</c> phase writes (EGRF v2, design §5).</summary>
public sealed record RecordSettings
{
    /// <summary>
    /// Simulated voting devices; ballot i goes to device i mod deviceCount, each with its own
    /// device section. Must be 1 under chaining (one device encrypts the whole chain).
    /// </summary>
    public int DeviceCount { get; init; } = 1;

    /// <summary>"protobuf" (<c>.binpb</c> segments) or "json" (<c>.jsonl</c>, the proto3 JSON mapping).</summary>
    public string Encoding { get; init; } = "protobuf";
}

public sealed record GuardianThreshold
{
    public int N { get; init; } = 3;
    public int K { get; init; } = 2;
}

/// <summary>
/// Which optional phases run. Encryption and aggregation always run -- they are the pipeline. Every
/// phase, mandatory or not, can still carry a budget.
/// </summary>
public sealed record PhaseSettings
{
    public bool BallotVerification { get; init; } = true;
    public bool TallyVerification { get; init; } = true;
    public bool Decrypt { get; init; } = true;
    public bool Serialization { get; init; } = true;

    /// <summary>
    /// Writes the election as an EGRF record (design §8.5) to a temporary directory as the run goes:
    /// the setup, each chunk appended to its device sections, the chains closed, voting and the
    /// aggregate sealed, and after decryption the final phase. Left out of the config hash when
    /// false, so a scenario without it keeps its earlier hash.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool WriteRecord { get; init; }

    /// <summary>
    /// Runs <c>ElectionRecordVerifier.VerifyAllAsync</c> (the full profile: Verifications 1-19 and
    /// every record rule) over the written record, from disk. Requires <see cref="WriteRecord"/>.
    /// Left out of the config hash when false.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool VerifyRecord { get; init; }
}

/// <summary>Command-line overrides. A null field leaves the scenario's value alone.</summary>
public sealed record ScenarioOverrides
{
    public int? BallotCount { get; init; }
    public int? Seed { get; init; }
    public int? Parallelism { get; init; }
    public int? ChunkSize { get; init; }
    public int? WarmupBallots { get; init; }
    public int? GuardianN { get; init; }
    public int? GuardianK { get; init; }
    public bool? BallotVerification { get; init; }
    public bool? TallyVerification { get; init; }
    public bool? Decrypt { get; init; }
    public bool? Serialization { get; init; }
    public bool? WriteRecord { get; init; }
    public bool? VerifyRecord { get; init; }

    public PerfScenario Apply(PerfScenario scenario)
    {
        var result = scenario with
        {
            BallotCount = BallotCount ?? scenario.BallotCount,
            Seed = Seed ?? scenario.Seed,
            Parallelism = Parallelism ?? scenario.Parallelism,
            ChunkSize = ChunkSize ?? scenario.ChunkSize,
            WarmupBallots = WarmupBallots ?? scenario.WarmupBallots,
            Guardians = new GuardianThreshold
            {
                N = GuardianN ?? scenario.Guardians.N,
                K = GuardianK ?? scenario.Guardians.K,
            },
            Phases = new PhaseSettings
            {
                BallotVerification = BallotVerification ?? scenario.Phases.BallotVerification,
                TallyVerification = TallyVerification ?? scenario.Phases.TallyVerification,
                Decrypt = Decrypt ?? scenario.Phases.Decrypt,
                Serialization = Serialization ?? scenario.Phases.Serialization,
                WriteRecord = WriteRecord ?? scenario.Phases.WriteRecord,
                VerifyRecord = VerifyRecord ?? scenario.Phases.VerifyRecord,
            },
        };

        ScenarioLoader.Validate(result);
        return result;
    }
}
