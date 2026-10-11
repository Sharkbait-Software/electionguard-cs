using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.RecordFormat;

namespace ElectionGuard.Core.Verify.Tally;

/// <summary>
/// Verification 9 (Correctness of ballot aggregation)
/// </summary>
public class BallotAggregationVerification
{
    /// <summary>
    /// Verification 9 on items decoded from the election record (design §4.8). The encrypted tally
    /// first: an A ≥ p fails 9.A and a B ≥ p 9.B (the recomputed product is below p, so it can never
    /// match), and another verification's finding on it leaves Verification 9 not evaluable
    /// (<see cref="RecordItemNotEvaluableException"/>). Then the ballots, read once: a ballot item with
    /// a finding has no domain object, so if it is a cast ballot the recomputed aggregate would miss
    /// a factor, and Verification 9 is not evaluable (rather than a false 9.A/9.B); a challenged or
    /// spoiled one is not aggregated and does not matter. Otherwise
    /// <see cref="Verify(IEnumerable{EncryptedBallot}, Manifest, EncryptedTally, int)"/>. See
    /// <see cref="RecordItemGate"/>.
    /// </summary>
    internal void Verify(IEnumerable<RecordDecoded<EncryptedBallot>> ballots, Manifest manifest, RecordDecoded<EncryptedTally> encryptedTally, int maxDegreeOfParallelism = -1)
    {
        var tally = RecordItemGate.Require(encryptedTally, 9);

        // Enumerated by the aggregation, which serializes MoveNext across its threads, so the
        // first undecodable cast ballot is recorded here and raised once the stream is consumed.
        RecordFinding? undecodable = null;
        IEnumerable<EncryptedBallot> Decodable()
        {
            foreach (var ballot in ballots)
            {
                if (ballot.Value is { } value)
                {
                    yield return value;
                }
                else if (ballot.Placeholder.Status == BallotStatus.Cast)
                {
                    undecodable ??= ballot.Findings[0];
                }
            }
        }

        var verifier = new BallotAggregationVerifier(manifest);
        verifier.AddBallots(Decodable(), maxDegreeOfParallelism);
        if (undecodable is not null)
        {
            throw new RecordItemNotEvaluableException(9, undecodable);
        }

        verifier.Verify(tally);
    }

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
