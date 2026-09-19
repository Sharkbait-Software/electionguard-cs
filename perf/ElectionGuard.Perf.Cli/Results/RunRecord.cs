namespace ElectionGuard.Perf.Cli.Results;

/// <summary>
/// One performance run. Persisted as a single JSON line; see RunRecordStore.
///
/// Phases contains only the phases that actually executed, so a run recorded before an expensive
/// phase became practical and a run recorded after it did are both valid records of their scenario.
/// Comparison code must intersect phase sets rather than reading an absent phase as zero.
/// </summary>
public sealed record RunRecord
{
    /// <summary>
    /// The record schema this build writes and is able to read. RunRecordStore refuses a line
    /// claiming a higher version rather than mis-deserializing a shape it does not know.
    /// </summary>
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;
    public required string RunId { get; init; }
    public required DateTimeOffset TimestampUtc { get; init; }

    /// <summary>Which encryptor produced this record. Other languages are planned.</summary>
    public string Implementation { get; init; } = "csharp";

    /// <summary>
    /// Shared by the records of a single --repeat invocation, so the spread across those runs is
    /// visible in the recorded history. Aggregation across a group (e.g. a median) is not yet
    /// implemented -- compare currently judges individual runs.
    /// </summary>
    public string? RepeatGroup { get; init; }

    public required ScenarioInfo Scenario { get; init; }
    public required SourceInfo Source { get; init; }
    public required EnvironmentInfo Environment { get; init; }
    public required SetupInfo Setup { get; init; }
    public required Dictionary<string, PhaseMetrics> Phases { get; init; }
    public required DerivedMetrics Derived { get; init; }
    public required MemoryMetrics Memory { get; init; }
    public SerializationMetrics? Serialization { get; init; }
    public required CorrectnessResult Correctness { get; init; }
    public Dictionary<string, string> Notes { get; init; } = new();
}

public sealed record ScenarioInfo
{
    public required string Id { get; init; }
    public required string ConfigHash { get; init; }
    public required string ManifestHash { get; init; }
    public required int BallotCount { get; init; }
    public required int Seed { get; init; }
    public required int GuardianN { get; init; }
    public required int GuardianK { get; init; }
    public required int Parallelism { get; init; }
    public required int ChunkSize { get; init; }
}

public sealed record SourceInfo
{
    public required string Commit { get; init; }
    public required string Branch { get; init; }
    public required bool Dirty { get; init; }
}

public sealed record EnvironmentInfo
{
    public required string MachineId { get; init; }
    public required string Cpu { get; init; }
    public required int LogicalCores { get; init; }
    public required int RamGb { get; init; }
    public required string Os { get; init; }
    public required string DotNet { get; init; }
    public required string GcMode { get; init; }
    public required string BuildConfig { get; init; }
}

public sealed record SetupInfo
{
    /// <summary>Distributed key generation. Reported but not part of any timed phase.</summary>
    public required double DkgMs { get; init; }
}

public sealed record PhaseMetrics
{
    public required double WallMs { get; init; }
    public required long AllocatedBytes { get; init; }
    public required GcCounts Gc { get; init; }

    /// <summary>
    /// How many ballots this phase actually covered. Equal to the scenario's ballotCount for a
    /// phase that ran to completion, and lower for one that hit its budget -- which is why derived
    /// per-ballot figures divide by this rather than by the scenario's ballotCount.
    /// </summary>
    public required int BallotsProcessed { get; init; }

    /// <summary>True when the phase stopped early on its budget. Its timings are partial.</summary>
    public bool Aborted { get; init; }
}

public sealed record GcCounts
{
    public int G0 { get; init; }
    public int G1 { get; init; }
    public int G2 { get; init; }
}

public sealed record DerivedMetrics
{
    public required double MsPerBallotEncrypt { get; init; }
    public required double BallotsPerSec { get; init; }
    public required double AllocBytesPerBallot { get; init; }
}

public sealed record MemoryMetrics
{
    public required long PeakManagedHeapBytes { get; init; }
    public required long PeakWorkingSetBytes { get; init; }
    public required long TotalAllocatedBytes { get; init; }
}

public sealed record SerializationMetrics
{
    public required SerializerMetrics Json { get; init; }
    public required SerializerMetrics Protobuf { get; init; }
}

public sealed record SerializerMetrics
{
    public required double SerializeOpsPerSec { get; init; }
    public required double DeserializeOpsPerSec { get; init; }
    public required long Bytes { get; init; }

    /// <summary>
    /// The shape of the ballot these figures were measured against -- one contest with two choices
    /// produces very different throughput/size numbers from a four-contest ballot, so a reader of a
    /// persisted result needs this to judge how representative the figures are.
    ///
    /// Deliberately NOT `required` and deliberately nullable, rather than defaulting to 0: this field
    /// was added after SchemaVersion 1 shipped, and RunRecordStore.ReadAll must still be able to read
    /// every already-recorded line, none of which carries it. `null` means "this record predates the
    /// field", which a bare 0 would misreport as "measured against an empty ballot". No SchemaVersion
    /// bump was needed for this -- PerfJson.LineOptions is already deliberately forward-compatible
    /// (see its doc comment): an older build ignores a field it doesn't know about, and a newer build
    /// reading an older line just gets null here instead of a value.
    /// </summary>
    public int? ContestCount { get; init; }

    /// <summary>Total selections across every contest on the measured ballot. See <see cref="ContestCount"/>.</summary>
    public int? SelectionCount { get; init; }
}

public static class CorrectnessStatus
{
    public const string Passed = "passed";
    public const string Failed = "failed";

    /// <summary>A phase the check depends on was aborted or skipped, so nothing was proven.</summary>
    public const string Incomplete = "incomplete";

    /// <summary>
    /// An exception ended the run. The record still carries every phase that completed before the
    /// throw, and notes["error"] carries the exception type and message -- a failed run is data.
    /// </summary>
    public const string Error = "error";

    /// <summary>Decryption was not requested, so there was nothing to check.</summary>
    public const string Skipped = "skipped";
}

public sealed record CorrectnessResult
{
    public required string Status { get; init; }
    public List<TallyMismatch> Mismatches { get; init; } = new();
}

public sealed record TallyMismatch
{
    public required string ContestId { get; init; }
    public required string ChoiceId { get; init; }
    public required int Expected { get; init; }
    public required int Actual { get; init; }
}
