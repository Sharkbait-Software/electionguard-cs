using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Verify;
using System.Collections.Concurrent;
using static ElectionGuard.Core.Tally.EncryptedTally;

namespace ElectionGuard.Core.Tally;

public class EncryptedTally
{
    public EncryptedTally(Manifest manifest)
    {
        _manifest = manifest;

        Contests = _manifest.Contests
            .ToDictionary(x => x.Id, x => new EncryptedAggregateContest
            {
                ContestId = x.Id,
                MaximumOptionValue = MaximumOptionValue(x),
                Choices = x.Choices.ToDictionary(ch => ch.Id, ch => new EncryptedAggregateChoice
                {
                    ChoiceId = ch.Id,
                    // ElGamal ciphertext multiplicative identity (alpha=1, beta=1), not the additive
                    // identity 0 -- so an aggregate with zero ballots added decrypts to vote count 0
                    // instead of failing TallyAdmin's discrete-log search.
                    A = new IntegerModP(1),
                    B = new IntegerModP(1),
                })
            });
    }

    /// <summary>
    /// Ballots per work item in <see cref="AddBallots"/>. Small enough to balance a chunk of a few
    /// hundred ballots across many cores, large enough that each worker's partial tally, which costs
    /// a few multiplies per choice to merge, is amortized over many ballots.
    /// </summary>
    private const int AddBallotsRangeSize = 16;

    private readonly Manifest _manifest;
    public Dictionary<string, EncryptedAggregateContest> Contests;

    /// <summary>The manifest this tally aggregates over. Its contests and options are the tally's keys.</summary>
    public Manifest Manifest => _manifest;

    /// <summary>
    /// The number of cast ballots added. Challenged ballots are not counted (see
    /// <see cref="AddBallot"/>). This is not the decryption bound: a weighted ballot, or one giving
    /// an option more than 1, adds more than 1 to a count; see
    /// <see cref="EncryptedAggregateChoice.MaximumCount"/>.
    /// </summary>
    public int BallotsCast { get; private set; } = 0;

    /// <summary>
    /// Multiplies a cast <paramref name="encryptedBallot"/>'s ciphertexts into the aggregate, each
    /// raised to the ballot's weight (eq. 80). Verification 9 recomputes the aggregate through this
    /// method, so its rejections are Verification 9 failures:
    /// <list type="bullet">
    /// <item>A <see cref="BallotStatus.Challenged"/> ballot is skipped: only cast ballots are
    /// aggregated (§3.5, Verification 9 "all cast ballots").</item>
    /// <item>A ballot with no recorded status (<see cref="BallotStatus.NotSubmitted"/>) is rejected
    /// with a <see cref="VerificationFailedException"/> of sub-section "9.structure": the record
    /// must say whether it was cast.</item>
    /// <item>A weight below 1 is rejected the same way. Eq. (80) weights are small positive
    /// integers; a weight of 0 or less used to be counted as 1 (G30).</item>
    /// <item>A ballot that does not list exactly its ballot style's contests and the manifest's
    /// options, each once, is rejected the same way before anything is multiplied in (see
    /// <see cref="BallotStructure"/>). Otherwise a contest or option listed twice would count
    /// twice.</item>
    /// </list>
    /// </summary>
    public void AddBallot(EncryptedBallot encryptedBallot)
    {
        if (encryptedBallot.Status == BallotStatus.Challenged)
        {
            return;
        }

        if (encryptedBallot.Status != BallotStatus.Cast)
        {
            throw new VerificationFailedException("9.structure",
                $"Ballot {encryptedBallot.Id} has status {encryptedBallot.Status}: only a ballot recorded as cast is aggregated, and only a challenged one is left out (§3.7, Verification 9).");
        }

        if (encryptedBallot.Weight < 1)
        {
            throw new VerificationFailedException("9.structure",
                $"Ballot {encryptedBallot.Id} has weight {encryptedBallot.Weight}: ballot weights are positive integers (eq. 80).");
        }

        BallotStructure.Require(encryptedBallot, _manifest, 9);

        foreach(var contest in encryptedBallot.Contests)
        {
            var aggregateContest = Contests[contest.Id];
            long maximumOptionContribution = (long)encryptedBallot.Weight * aggregateContest.MaximumOptionValue;
            foreach(var choice in contest.Choices)
            {
                var aggregateChoice = aggregateContest.Choices[choice.ChoiceId];
                aggregateChoice.MaximumCount += maximumOptionContribution;

                if(encryptedBallot.Weight > 1)
                {
                    // A ballot weight is a small public integer, not a nonce, so it is raised with a
                    // window that walks only the weight's own bits rather than the full width of Z_q.
                    aggregateChoice.AProduct.MultiplyPower(choice.Alpha, encryptedBallot.Weight);
                    aggregateChoice.BProduct.MultiplyPower(choice.Beta, encryptedBallot.Weight);
                }
                else
                {
                    aggregateChoice.AProduct.Multiply(choice.Alpha);
                    aggregateChoice.BProduct.Multiply(choice.Beta);
                }
            }
        }
        BallotsCast++;
    }

    /// <summary>
    /// Adds every ballot in <paramref name="encryptedBallots"/>, with the same result as calling
    /// <see cref="AddBallot"/> on each in turn, spread across up to
    /// <paramref name="maxDegreeOfParallelism"/> threads (-1, the default, for no limit). Aggregation
    /// is a product, so it does not depend on order: each worker accumulates its own partial tally,
    /// and the partial tallies are then multiplied into this one, each choice on its own thread.
    /// </summary>
    public void AddBallots(IReadOnlyList<EncryptedBallot> encryptedBallots, int maxDegreeOfParallelism = -1)
    {
        if (maxDegreeOfParallelism == 1 || encryptedBallots.Count <= AddBallotsRangeSize)
        {
            foreach (var encryptedBallot in encryptedBallots)
            {
                AddBallot(encryptedBallot);
            }

            return;
        }

        var options = new ParallelOptions { MaxDegreeOfParallelism = maxDegreeOfParallelism };
        var partials = new List<EncryptedTally>();
        Parallel.ForEach(
            Partitioner.Create(0, encryptedBallots.Count, AddBallotsRangeSize),
            options,
            () => new EncryptedTally(_manifest),
            (range, _, partial) =>
            {
                for (int i = range.Item1; i < range.Item2; i++)
                {
                    partial.AddBallot(encryptedBallots[i]);
                }

                return partial;
            },
            partial =>
            {
                lock (partials)
                {
                    partials.Add(partial);
                }
            });

        MergePartials(partials, options);
    }

    /// <summary>
    /// Adds every ballot <paramref name="encryptedBallots"/> yields, enumerating it exactly once, with
    /// the same result as calling <see cref="AddBallot"/> on each, spread across up to
    /// <paramref name="maxDegreeOfParallelism"/> threads (-1, the default, for no limit).
    ///
    /// For a source too large to hold, such as ballots read lazily from an election record: workers
    /// take ballots one at a time, so at most one per worker is in flight beyond whatever the source
    /// itself buffers, and each worker keeps a single partial tally for the whole stream rather than
    /// one per batch. A source that is already a list takes the
    /// <see cref="AddBallots(IReadOnlyList{EncryptedBallot}, int)"/> path.
    /// </summary>
    public void AddBallots(IEnumerable<EncryptedBallot> encryptedBallots, int maxDegreeOfParallelism = -1)
    {
        if (encryptedBallots is IReadOnlyList<EncryptedBallot> list)
        {
            AddBallots(list, maxDegreeOfParallelism);
            return;
        }

        if (maxDegreeOfParallelism == 1)
        {
            foreach (var encryptedBallot in encryptedBallots)
            {
                AddBallot(encryptedBallot);
            }

            return;
        }

        // NoBuffering: the default partitioner hands out chunks that grow to hundreds of elements per
        // worker, which for ballots of tens of kilobytes each would hold gigabytes in flight.
        //
        // Pooled partials: Parallel.ForEach's workers yield their thread every few hundred
        // milliseconds and resume as new tasks, each running localInit again. Allocating a fresh
        // partial there would grow the set with the stream's duration, not its parallelism -- several
        // GB over a long one. Returned to the pool on yield and taken back on resume, no more
        // partials exist than workers ever ran at once.
        var options = new ParallelOptions { MaxDegreeOfParallelism = maxDegreeOfParallelism };
        var pool = new ConcurrentBag<EncryptedTally>();
        Parallel.ForEach(
            Partitioner.Create(encryptedBallots, EnumerablePartitionerOptions.NoBuffering),
            options,
            () => pool.TryTake(out var partial) ? partial : new EncryptedTally(_manifest),
            (encryptedBallot, _, partial) =>
            {
                partial.AddBallot(encryptedBallot);
                return partial;
            },
            pool.Add);

        MergePartials(pool.ToList(), options);
    }

    private void MergePartials(List<EncryptedTally> partials, ParallelOptions options)
    {
        // Merging under the lock in AddBallots serialized a multiply per choice per worker, which on
        // many cores cost more than the aggregation itself. Merged choice by choice instead, each
        // choice's products are touched by one thread only.
        var choices = Contests
            .SelectMany(contest => contest.Value.Choices.Select(choice => (ContestId: contest.Key, Choice: choice.Value)))
            .ToArray();
        Parallel.For(0, choices.Length, options, i =>
        {
            var (contestId, choice) = choices[i];
            foreach (var partial in partials)
            {
                var partialChoice = partial.Contests[contestId].Choices[choice.ChoiceId];
                choice.AProduct.Multiply(partialChoice.AProduct);
                choice.BProduct.Multiply(partialChoice.BProduct);
                choice.MaximumCount += partialChoice.MaximumCount;
            }
        });

        BallotsCast += partials.Sum(partial => partial.BallotsCast);
    }

    /// <summary>
    /// The most one cast ballot of weight 1 can add to one option's count in
    /// <paramref name="contest"/>: an option takes at most R = <see cref="Contest.OptionSelectionLimit"/>
    /// (§3.3.7) and all options together at most L = <see cref="Contest.SelectionLimit"/>, so
    /// min(R, L). (A total above L is an overvote, which the encryptor turns into all zeros; a
    /// ballot whose option value exceeds this cannot carry valid range proofs.)
    ///
    /// Stage S5 adds the supplemental fields (overvote, null vote, undervote and write-in counts) as
    /// options with bounds of their own (1 for an indicator, L for the undervote difference count,
    /// the number of write-in fields for the write-in count); their bound belongs here, per option.
    /// </summary>
    internal static int MaximumOptionValue(Contest contest)
    {
        return Math.Max(0, Math.Min(contest.OptionSelectionLimit, contest.SelectionLimit));
    }

    public class EncryptedAggregateContest
    {
        public required string ContestId { get; init; }
        public required Dictionary<string, EncryptedAggregateChoice> Choices { get; init; }

        /// <summary>See <see cref="EncryptedTally.MaximumOptionValue"/>.</summary>
        internal int MaximumOptionValue { get; init; }
    }

    public class EncryptedAggregateChoice
    {
        public required string ChoiceId { get; init; }

        /// <summary>
        /// The largest count this choice's aggregate can encrypt: the sum, over the cast ballots added,
        /// of the ballot's weight W (eq. 80) times the most one ballot can give the option,
        /// min(R, L). Tally decryption searches [0, this] for the count (§3.6.2); the number of
        /// ballots cast, which it used to search, is too small once a weight or R exceeds 1 (G16).
        /// Public, since a decrypting administrator reads it, but not a verified value: nothing in
        /// Verifications 9 to 11 depends on it. Only <see cref="AddBallot"/> and
        /// <see cref="MergePartials"/> set it: a tally rebuilt through the <see cref="A"/> and
        /// <see cref="B"/> setters (from a published record, say) has 0 here, so decrypting it fails
        /// closed for any nonzero count. Restoring it from outside Core is S10's record-loading work.
        /// </summary>
        public long MaximumCount { get; internal set; }

        /// <summary>
        /// The aggregate alpha, the product of every added ballot's alpha for this choice. Held as a
        /// running Montgomery-form product between additions; reading it converts it out (cached
        /// until the next addition), and setting it restarts the product from the value set.
        /// </summary>
        public required IntegerModP A
        {
            get => AProduct.Value;
            set => AProduct.Reset(value);
        }

        /// <summary>The aggregate beta. See <see cref="A"/>.</summary>
        public required IntegerModP B
        {
            get => BProduct.Value;
            set => BProduct.Reset(value);
        }

        internal ModPProduct AProduct { get; } = new(1);

        internal ModPProduct BProduct { get; } = new(1);

        public bool IsZero()
        {
            return A == 1 && B == 1;
        }
    }
}
