using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;

namespace ElectionGuard.Core.Verify.Tally;

/// <summary>
/// Verification 9 (Correctness of ballot aggregation), performed incrementally.
///
/// Verification 9 checks, for every option of every contest, that the claimed aggregate (A, B)
/// equals the product of the corresponding (alpha, beta) over every cast ballot (9.A, 9.B). That
/// product does not depend on the order or grouping of the ballots, so it can be built up as the
/// ballots arrive -- in chunks, from a stream, or across several sources -- and compared once at the
/// end. Nothing here retains a ballot: memory is one running product per option, however many
/// ballots are added.
///
/// The recomputation is this verifier's own <see cref="EncryptedTally"/>, never the claimed one:
/// the verifier must reach its expected values independently of the record it is checking.
///
/// Adding is not atomic. A ballot that does not have its ballot style's structure (see
/// <see cref="BallotStructure"/>; reported as sub-section "9.structure") is rejected before any of
/// its own ciphertexts are multiplied in, but depending on chunk size and parallelism some of its
/// neighbours' already have been, so what survives would depend on how the ballots were grouped.
/// Rather than expose that, any exception out of <see cref="AddBallot"/> or
/// <see cref="AddBallots"/> faults the verifier: every later <see cref="Verify"/> throws
/// <see cref="InvalidOperationException"/>, and a caller that wants to skip malformed ballots must
/// start a new verifier.
/// </summary>
public class BallotAggregationVerifier
{
    private readonly EncryptedTally _expected;

    /// <summary>
    /// Set when an addition threw, leaving <see cref="_expected"/> holding an unknown part of the
    /// ballots it was given. See the class remarks.
    /// </summary>
    private bool _faulted;

    /// <summary>
    /// Starts an empty recomputation over the contests and options of <paramref name="manifest"/>.
    /// </summary>
    public BallotAggregationVerifier(Manifest manifest)
    {
        _expected = new EncryptedTally(manifest);
    }

    /// <summary>
    /// The number of ballots added so far. Not part of Verification 9, which compares only the
    /// aggregate ciphertexts; exposed so a caller can check it against the claimed tally's
    /// <see cref="EncryptedTally.BallotsCast"/> or the record's own count if it chooses.
    /// </summary>
    public int BallotsAdded => _expected.BallotsCast;

    /// <summary>
    /// Folds <paramref name="encryptedBallot"/> into the recomputed aggregate. If this throws, the
    /// verifier is faulted and <see cref="Verify"/> will refuse to run.
    /// </summary>
    public void AddBallot(EncryptedBallot encryptedBallot)
    {
        try
        {
            _expected.AddBallot(encryptedBallot);
        }
        catch
        {
            _faulted = true;
            throw;
        }
    }

    /// <summary>
    /// Folds every ballot in <paramref name="encryptedBallots"/> into the recomputed aggregate on up
    /// to <paramref name="maxDegreeOfParallelism"/> threads (-1, the default, for no limit), with
    /// the same result as calling <see cref="AddBallot"/> on each. If this throws, the verifier is
    /// faulted and <see cref="Verify"/> will refuse to run.
    /// </summary>
    public void AddBallots(IReadOnlyList<EncryptedBallot> encryptedBallots, int maxDegreeOfParallelism = -1)
    {
        try
        {
            _expected.AddBallots(encryptedBallots, maxDegreeOfParallelism);
        }
        catch
        {
            _faulted = true;
            throw;
        }
    }

    /// <summary>
    /// Folds every ballot <paramref name="encryptedBallots"/> yields into the recomputed aggregate,
    /// enumerating it exactly once on up to <paramref name="maxDegreeOfParallelism"/> threads,
    /// without holding more than one ballot per thread. See
    /// <see cref="EncryptedTally.AddBallots(IEnumerable{EncryptedBallot}, int)"/>. If this throws,
    /// the verifier is faulted and <see cref="Verify"/> will refuse to run.
    /// </summary>
    public void AddBallots(IEnumerable<EncryptedBallot> encryptedBallots, int maxDegreeOfParallelism = -1)
    {
        try
        {
            _expected.AddBallots(encryptedBallots, maxDegreeOfParallelism);
        }
        catch
        {
            _faulted = true;
            throw;
        }
    }

    /// <summary>
    /// Checks 9.A and 9.B for each option in each contest in the election manifest (p.45): the
    /// claimed aggregate (A, B) in <paramref name="encryptedTally"/> must equal the product of the
    /// cast ballots added so far. Throws <see cref="VerificationFailedException"/>:
    /// <list type="bullet">
    /// <item>"9.structure" if the claimed tally's contests and options are not exactly the
    /// manifest's: an option the manifest lists is missing (it would otherwise never be compared,
    /// G20), or the tally carries a contest or option the manifest does not. Checked for every key
    /// before any value is compared.</item>
    /// <item>"9.A" or "9.B", naming the first contest and option in manifest order whose A or B
    /// differs.</item>
    /// </list>
    ///
    /// Does not consume or reset the recomputation: more ballots may be added afterwards and
    /// <see cref="Verify"/> called again against a later claimed tally.
    ///
    /// Throws <see cref="InvalidOperationException"/> instead, without comparing anything, if an
    /// earlier addition threw: the recomputation no longer corresponds to any set of whole ballots.
    /// </summary>
    public void Verify(EncryptedTally encryptedTally)
    {
        if (_faulted)
        {
            throw new InvalidOperationException(
                "Ballot aggregation verification cannot run: an earlier AddBallot or AddBallots call threw, " +
                "so the recomputed aggregate holds an unknown part of the ballots it was given.");
        }

        var manifest = _expected.Manifest;

        // The keys first, both ways: every manifest option, and every supplemental field the
        // manifest declares (§3.1.3 p.19: they are listed with the options), must be in the claimed
        // tally, and the claimed tally may hold nothing else.
        foreach (var contest in manifest.Contests)
        {
            if (!encryptedTally.Contests.TryGetValue(contest.Id, out var claimedContest))
            {
                throw new VerificationFailedException("9.structure", $"Ballot aggregation verification failed: the tally has no aggregate for manifest contest {contest.Id}.");
            }

            foreach (var choice in contest.VerifiableFields())
            {
                if (!claimedContest.Choices.ContainsKey(choice.Id))
                {
                    throw new VerificationFailedException("9.structure", $"Ballot aggregation verification failed: the tally has no aggregate for option {choice.Id} of manifest contest {contest.Id}.");
                }
            }

            if (claimedContest.Choices.Count != contest.VerifiableFieldCount())
            {
                var extra = claimedContest.Choices.Keys.First(id => !contest.VerifiableFields().Any(choice => choice.Id == id));
                throw new VerificationFailedException("9.structure", $"Ballot aggregation verification failed: the tally has an aggregate for option {extra} of contest {contest.Id}, which the manifest does not list.");
            }
        }

        if (encryptedTally.Contests.Count != manifest.Contests.Count)
        {
            var extra = encryptedTally.Contests.Keys.First(id => !manifest.Contests.Any(contest => contest.Id == id));
            throw new VerificationFailedException("9.structure", $"Ballot aggregation verification failed: the tally has an aggregate for contest {extra}, which the manifest does not list.");
        }

        foreach (var contest in manifest.Contests)
        {
            var expectedContest = _expected.Contests[contest.Id];
            var claimedContest = encryptedTally.Contests[contest.Id];
            foreach (var choice in contest.VerifiableFields())
            {
                var expectedChoice = expectedContest.Choices[choice.Id];
                var claimedChoice = claimedContest.Choices[choice.Id];
                if (expectedChoice.A != claimedChoice.A)
                {
                    throw new VerificationFailedException("9.A", $"Ballot aggregation verification failed for contest {contest.Id}, choice {choice.Id}: expected A {expectedChoice.A}, got {claimedChoice.A}");
                }
                if (expectedChoice.B != claimedChoice.B)
                {
                    throw new VerificationFailedException("9.B", $"Ballot aggregation verification failed for contest {contest.Id}, choice {choice.Id}: expected B {expectedChoice.B}, got {claimedChoice.B}");
                }
            }
        }
    }
}
