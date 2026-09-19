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
            },
        };

        ScenarioLoader.Validate(result);
        return result;
    }
}
