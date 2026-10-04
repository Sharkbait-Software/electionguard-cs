using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;

namespace ElectionGuard.Core.Verify.Tally;

/// <summary>
/// Verification 9 (Correctness of ballot aggregation)
/// </summary>
public class BallotAggregationVerification
{
    /// <summary>
    /// Recomputes the aggregate from <paramref name="ballots"/> on up to
    /// <paramref name="maxDegreeOfParallelism"/> threads (-1, the default, for no limit) and checks
    /// it against <paramref name="encryptedTally"/>.
    ///
    /// <paramref name="ballots"/> is enumerated once and need not fit in memory: a lazily read
    /// sequence is held at most one ballot per thread. A caller that produces its ballots itself in
    /// batches, and wants to interleave other work between them, should drive
    /// <see cref="BallotAggregationVerifier"/>, which this wraps.
    /// </summary>
    public void Verify(IEnumerable<EncryptedBallot> ballots, Manifest manifest, EncryptedTally encryptedTally, int maxDegreeOfParallelism = -1)
    {
        var verifier = new BallotAggregationVerifier(manifest);
        verifier.AddBallots(ballots, maxDegreeOfParallelism);
        verifier.Verify(encryptedTally);
    }
}
