using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Perf.Cli.Results;

namespace ElectionGuard.Perf.Cli.Running;

public sealed record RunOutcome
{
    /// <summary>Only the phases that actually executed.</summary>
    public required Dictionary<string, PhaseMetrics> Phases { get; init; }

    public required MemoryMetrics Memory { get; init; }
    public required CorrectnessResult Correctness { get; init; }
    public required double DkgMs { get; init; }
    public required Dictionary<string, string> Notes { get; init; }
    public required int BallotsEncrypted { get; init; }

    /// <summary>
    /// One encrypted ballot retained for the serialization benchmark, which measures a single
    /// ballot round-tripped repeatedly rather than the whole corpus.
    /// </summary>
    public EncryptedBallot? RepresentativeBallot { get; init; }
}
