using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
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
        : this(manifest, allowAvx512: true)
    {
    }

    /// <summary>With <paramref name="allowAvx512"/> false the recomputation runs on the scalar engine (a test seam; see <see cref="EncryptedTally"/>).</summary>
    internal BallotAggregationVerifier(Manifest manifest, bool allowAvx512)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        _expected = new EncryptedTally(manifest, allowAvx512);
    }

    /// <summary>Whether an addition threw, so that <see cref="Verify"/> refuses to run (see the class remarks).</summary>
    public bool IsFaulted => _faulted;

    /// <summary>
    /// The recomputation so far in standard form (design §6.7, §6.8): per contest its cast weight and
    /// per field (A, B) as ordinary residues mod p, b(A, 512) and b(B, 512), plus the counts and
    /// whether the verifier is faulted. The running products inside carry engine-specific Montgomery
    /// drift (R differs between the AVX-512 and the scalar engine; <c>ModPProduct</c>), so this is the
    /// only form that may leave the process: a checkpoint or another machine's shard.
    /// </summary>
    public BallotAggregationPartial ExportStandardForm()
    {
        var contests = _expected.Manifest.Contests.Select(contest =>
        {
            var aggregate = _expected.Contests[contest.Id];
            var choices = contest.VerifiableFields().Select(field =>
            {
                var choice = aggregate.Choices[field.Id];
                return new BallotAggregationPartial.Choice(field.Id, choice.A.ToByteArray(), choice.B.ToByteArray());
            }).ToList();
            return new BallotAggregationPartial.Contest(contest.Id, aggregate.CastWeight, choices);
        }).ToList();
        return new BallotAggregationPartial(_faulted, _expected.BallotsCast, _expected.TotalCastWeight, contests);
    }

    /// <summary>A verifier continuing from <paramref name="partial"/>, which must be over <paramref name="manifest"/>'s contests and fields.</summary>
    public static BallotAggregationVerifier ImportStandardForm(Manifest manifest, BallotAggregationPartial partial)
    {
        var verifier = new BallotAggregationVerifier(manifest);
        verifier.Merge(partial);
        return verifier;
    }

    /// <summary>
    /// Multiplies <paramref name="other"/>'s recomputation into this one (design §6.7: the V9 partials
    /// of workers or shards commute and merge), through the standard form, so the two may run on
    /// different engines. A faulted operand faults the result.
    /// </summary>
    public void Merge(BallotAggregationVerifier other)
    {
        ArgumentNullException.ThrowIfNull(other);
        Merge(other.ExportStandardForm());
    }

    /// <summary>
    /// Multiplies a standard-form partial into this recomputation: each field's (A, B), each contest's
    /// cast weight and the counts. Throws <see cref="ArgumentException"/>, changing nothing, unless the
    /// partial holds exactly this manifest's contests and fields with 512-byte values below p. A
    /// faulted partial faults this verifier.
    /// </summary>
    public void Merge(BallotAggregationPartial partial)
    {
        ArgumentNullException.ThrowIfNull(partial);
        var manifest = _expected.Manifest;
        var values = new List<(EncryptedTally.EncryptedAggregateChoice Choice, IntegerModP A, IntegerModP B)>();
        if (partial.Contests.Count != manifest.Contests.Count)
        {
            throw new ArgumentException($"The partial holds {partial.Contests.Count} contests; the manifest has {manifest.Contests.Count}.", nameof(partial));
        }

        for (int i = 0; i < manifest.Contests.Count; i++)
        {
            var contest = manifest.Contests[i];
            var given = partial.Contests[i];
            var fields = contest.VerifiableFields().ToList();
            if (given.ContestId != contest.Id || given.Choices.Count != fields.Count || given.CastWeight < 0)
            {
                throw new ArgumentException($"The partial's contest {i} is not manifest contest {contest.Id} with its {fields.Count} fields.", nameof(partial));
            }

            for (int j = 0; j < fields.Count; j++)
            {
                var choice = given.Choices[j];
                if (choice.ChoiceId != fields[j].Id)
                {
                    throw new ArgumentException($"The partial's field {j} of contest {contest.Id} is {choice.ChoiceId}, not {fields[j].Id}.", nameof(partial));
                }

                values.Add((_expected.Contests[contest.Id].Choices[choice.ChoiceId], Residue(choice.A, contest.Id, choice.ChoiceId), Residue(choice.B, contest.Id, choice.ChoiceId)));
            }
        }

        foreach (var (choice, a, b) in values)
        {
            choice.AProduct.Multiply(a);
            choice.BProduct.Multiply(b);
        }

        foreach (var given in partial.Contests)
        {
            _expected.Contests[given.ContestId].CastWeight += given.CastWeight;
        }

        _expected.BallotsCast += partial.BallotsAdded;
        _expected.TotalCastWeight += partial.WeightAdded;
        _faulted |= partial.Faulted;

        static IntegerModP Residue(byte[] bytes, string contestId, string choiceId)
        {
            if (bytes is not { Length: 512 } || new System.Numerics.BigInteger(bytes, isUnsigned: true, isBigEndian: true) >= EGParameters.P)
            {
                throw new ArgumentException($"The partial's value for contest {contestId}, field {choiceId} is not 512 bytes below p.", nameof(partial));
            }

            return new IntegerModP(bytes);
        }
    }

    /// <summary>
    /// The number of cast ballots added so far. Not part of Verification 9, which compares only the
    /// aggregate ciphertexts; the election record's header claim is checked against it by
    /// <see cref="VerifySummary"/>.
    /// </summary>
    public int BallotsAdded => _expected.BallotsCast;

    /// <summary>
    /// The total weight of the cast ballots added so far (the sum of their weights, §3.5). Not part
    /// of Verification 9; see <see cref="BallotsAdded"/>.
    /// </summary>
    public long WeightAdded => _expected.TotalCastWeight;

    /// <summary>
    /// Design §6.1 step E: the encrypted tally header's <c>cast_ballot_count</c> and
    /// <c>total_cast_weight</c> (#17), which a tally decoded from the record carries as
    /// <see cref="EncryptedTally.BallotsCast"/> and <see cref="EncryptedTally.TotalCastWeight"/>,
    /// must equal <see cref="BallotsAdded"/> and <see cref="WeightAdded"/>. The spec publishes
    /// neither and nothing is computed from them, so decoding adds no finding and this is not part
    /// of Verification 9: a disagreement is <see cref="VerificationFailedException"/> "R.summary", a
    /// record-level code, which the record verifier (S10b-9) reports beside Verification 9's
    /// outcome, never as it. Throws <see cref="InvalidOperationException"/> instead if an earlier
    /// addition threw (see the class remarks).
    /// </summary>
    internal void VerifySummary(EncryptedTally encryptedTally)
    {
        ArgumentNullException.ThrowIfNull(encryptedTally);
        if (_faulted)
        {
            throw new InvalidOperationException(
                "The record summary cannot be checked: an earlier AddBallot or AddBallots call threw, " +
                "so the recount holds an unknown part of the ballots it was given.");
        }

        if (encryptedTally.BallotsCast != BallotsAdded)
        {
            throw new VerificationFailedException("R.summary", $"The encrypted tally header counts {encryptedTally.BallotsCast} cast ballots; the record holds {BallotsAdded}.");
        }

        if (encryptedTally.TotalCastWeight != WeightAdded)
        {
            throw new VerificationFailedException("R.summary", $"The encrypted tally header gives a total cast weight of {encryptedTally.TotalCastWeight}; the record's cast ballots weigh {WeightAdded}.");
        }
    }

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
    /// <item>"9.structure", after 9.A and 9.B, if a contest's published cast weight
    /// (<see cref="EncryptedTally.EncryptedAggregateContest.CastWeight"/>, the sum of the weights of
    /// the cast ballots that list it) differs from the recomputed one. The spec publishes no such
    /// value; the library does, because it bounds each count's decryption search when the tally is
    /// read back from a record (S10a).</item>
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

        // Not 9.A/9.B (the spec publishes no cast weight), so checked after them: the published
        // per-contest cast weight bounds each count's decryption search (EncryptedAggregateChoice.
        // MaximumCount). A tally read back from a record takes it from the document (S10a), so a
        // wrong weight would narrow the administrator's search (decryption fails) or widen it (time
        // and memory), and is refused here. The ballot count is not compared: it bounds nothing,
        // and one ballot of weight 3 aggregates exactly as three of weight 1 (see BallotsAdded).
        foreach (var contest in manifest.Contests)
        {
            long expectedWeight = _expected.Contests[contest.Id].CastWeight;
            long claimedWeight = encryptedTally.Contests[contest.Id].CastWeight;
            if (expectedWeight != claimedWeight)
            {
                throw new VerificationFailedException("9.structure", $"Ballot aggregation verification failed for contest {contest.Id}: the tally gives a cast weight of {claimedWeight}, but the cast ballots that list the contest weigh {expectedWeight} (eq. 80).");
            }
        }
    }
}

/// <summary>
/// A Verification 9 recomputation in standard form (<see cref="BallotAggregationVerifier.ExportStandardForm"/>):
/// the counts, whether it is faulted, and per manifest contest, in manifest order, the cast weight and
/// per verifiable field, in manifest order, (A, B) as 512-byte big-endian residues mod p. Engine
/// independent, so it may cross a process or machine boundary (design §6.7) or be checkpointed (§6.8).
/// </summary>
public sealed record BallotAggregationPartial(bool Faulted, int BallotsAdded, long WeightAdded, IReadOnlyList<BallotAggregationPartial.Contest> Contests)
{
    /// <summary>One contest: its label, its cast weight and its fields.</summary>
    public sealed record Contest(string ContestId, long CastWeight, IReadOnlyList<Choice> Choices);

    /// <summary>One verifiable field: its label and b(A, 512), b(B, 512).</summary>
    public sealed record Choice(string ChoiceId, byte[] A, byte[] B);
}
