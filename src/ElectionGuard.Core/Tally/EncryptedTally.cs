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
        : this(manifest, allowAvx512: true)
    {
    }

    /// <summary>
    /// With <paramref name="allowAvx512"/> false every running product uses the scalar Montgomery
    /// engine even where AVX-512F is available (<see cref="ModPProduct"/>), so that tests can merge
    /// partials built on the two engines through the standard form.
    /// </summary>
    internal EncryptedTally(Manifest manifest, bool allowAvx512)
    {
        _manifest = manifest;
        _allowAvx512 = allowAvx512;

        // One aggregate per verifiable field of each contest: its selectable options and the
        // supplemental fields it declares (§3.1.3 p.19, §3.3.9 "allow verifiable tallies that show
        // the total numbers of undervotes, null votes, overvotes, or used write-in fields"), keyed by
        // label. Option and field labels are unique within a contest (Manifest.Validate).
        Contests = _manifest.Contests.ToDictionary(x => x.Id, x => CreateAggregateContest(x, allowAvx512));
    }

    private readonly bool _allowAvx512 = true;

    private static EncryptedAggregateContest CreateAggregateContest(Contest contest, bool allowAvx512)
    {
        var aggregate = new EncryptedAggregateContest
        {
            ContestId = contest.Id,
            Choices = new Dictionary<string, EncryptedAggregateChoice>(contest.VerifiableFieldCount()),
        };

        foreach (var field in contest.VerifiableFields())
        {
            aggregate.Choices.Add(field.Id, new EncryptedAggregateChoice
            {
                ScalarEngine = !allowAvx512,
                ChoiceId = field.Id,
                MaximumValue = MaximumOptionValue(contest, field),
                Contest = aggregate,
                // ElGamal ciphertext multiplicative identity (alpha=1, beta=1), not the additive
                // identity 0 -- so an aggregate with zero ballots added decrypts to vote count 0
                // instead of failing TallyAdmin's discrete-log search.
                A = new IntegerModP(1),
                B = new IntegerModP(1),
            });
        }

        return aggregate;
    }

    /// <summary>
    /// Rebuilds a tally from its published form (<see cref="Serialization.JsonElectionRecordSerializer"/>):
    /// every contest and option the document lists, with its (A, B) and cast weight, and the number
    /// of ballots cast. The keys are the document's, not the manifest's, so that Verification 9 sees
    /// a contest or option the manifest does not list, or misses one it does ("9.structure"). Each
    /// option's <see cref="EncryptedAggregateChoice.MaximumValue"/> comes from
    /// <paramref name="manifest"/> (0 for a label it does not have), so
    /// <see cref="EncryptedAggregateChoice.MaximumCount"/>, the decryption bound, is restored from the
    /// published cast weight (S4 review R1/F2, S10a).
    /// </summary>
    internal static EncryptedTally Restore(
        Manifest manifest,
        int ballotsCast,
        IEnumerable<(string ContestId, long CastWeight, IEnumerable<(string ChoiceId, IntegerModP A, IntegerModP B)> Choices)> contests)
    {
        var tally = new EncryptedTally(manifest)
        {
            BallotsCast = ballotsCast,
        };

        var restored = new Dictionary<string, EncryptedAggregateContest>(StringComparer.Ordinal);
        foreach (var (contestId, castWeight, choices) in contests)
        {
            var manifestContest = manifest.Contests.FirstOrDefault(x => string.Equals(x.Id, contestId, StringComparison.Ordinal));
            var aggregate = new EncryptedAggregateContest
            {
                ContestId = contestId,
                Choices = new Dictionary<string, EncryptedAggregateChoice>(StringComparer.Ordinal),
                CastWeight = castWeight,
            };

            foreach (var (choiceId, a, b) in choices)
            {
                var field = manifestContest?.VerifiableFields().FirstOrDefault(x => string.Equals(x.Id, choiceId, StringComparison.Ordinal));
                if (!aggregate.Choices.TryAdd(choiceId, new EncryptedAggregateChoice
                {
                    ChoiceId = choiceId,
                    MaximumValue = field is null ? 0 : MaximumOptionValue(manifestContest!, field),
                    Contest = aggregate,
                    A = a,
                    B = b,
                }))
                {
                    throw new ArgumentException($"The tally lists option {choiceId} of contest {contestId} twice.");
                }
            }

            if (!restored.TryAdd(contestId, aggregate))
            {
                throw new ArgumentException($"The tally lists contest {contestId} twice.");
            }
        }

        tally.Contests = restored;
        return tally;
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
    /// The number of cast ballots added. Challenged and spoiled ballots are not counted (see
    /// <see cref="AddBallot"/>). This is not the decryption bound: a weighted ballot, or one giving
    /// an option more than 1, adds more than 1 to a count; see
    /// <see cref="EncryptedAggregateChoice.MaximumCount"/>. Published with the tally for
    /// information; Verification 9 does not compare it (it bounds nothing; the per-contest
    /// <see cref="EncryptedAggregateContest.CastWeight"/> does, and is compared). The election
    /// record's header claim of it is checked against the recount as "R.summary"
    /// (<see cref="Verify.Tally.BallotAggregationVerifier.VerifySummary"/>, design §6.1 step E).
    /// </summary>
    public int BallotsCast { get; internal set; } = 0;

    /// <summary>
    /// The sum of the weights W (eq. 80) of the cast ballots added, whatever contests they list:
    /// the election record's <c>EncryptedTallyHeader.total_cast_weight</c> (design §4.5, #17),
    /// informational like <see cref="BallotsCast"/> (decoding adds no finding; the record verifier
    /// checks the header against the recount as "R.summary"). A tally restored from the JSON record format,
    /// which does not publish it, has 0 here, and the record writer refuses it
    /// (<c>TallyMapper.ToItems</c>: a total below <see cref="BallotsCast"/> is unknown, since every
    /// weight is at least 1).
    /// </summary>
    public long TotalCastWeight { get; internal set; }

    /// <summary>
    /// Multiplies a cast <paramref name="encryptedBallot"/>'s ciphertexts into the aggregate, each
    /// raised to the ballot's weight (eq. 80). Verification 9 recomputes the aggregate through this
    /// method, so its rejections are Verification 9 failures:
    /// <list type="bullet">
    /// <item>A <see cref="BallotStatus.Challenged"/> or <see cref="BallotStatus.Spoiled"/> ballot
    /// is skipped: only cast ballots are aggregated (§3.5, Verification 9 "all cast ballots").</item>
    /// <item>A ballot with no recorded status (<see cref="BallotStatus.Unrecorded"/>), or with a
    /// value that is not a status, is rejected with a <see cref="VerificationFailedException"/> of
    /// sub-section "9.structure": the record must say whether it was cast.</item>
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
        if (encryptedBallot.Status is BallotStatus.Challenged or BallotStatus.Spoiled)
        {
            return;
        }

        if (encryptedBallot.Status != BallotStatus.Cast)
        {
            throw new VerificationFailedException("9.structure",
                $"Ballot {encryptedBallot.Id} has status {encryptedBallot.Status}: only a ballot recorded as cast is aggregated, and only a challenged or spoiled one is left out (§3.7, Verification 9).");
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

            // The ballot lists every option and declared field of the contest (BallotStructure), so
            // each of them can grow by at most this ballot's weight times its own maximum.
            aggregateContest.CastWeight += encryptedBallot.Weight;
            foreach(var choice in contest.Choices)
            {
                Add(aggregateContest.Choices[choice.ChoiceId], choice, encryptedBallot.Weight);
            }

            // The supplemental fields are aggregated exactly as options are (G29), so their totals
            // are decrypted and verified with the options'.
            foreach (var field in contest.SupplementalFields)
            {
                Add(aggregateContest.Choices[field.FieldId], field, encryptedBallot.Weight);
            }
        }
        BallotsCast++;
        TotalCastWeight += encryptedBallot.Weight;
    }

    private static void Add(EncryptedAggregateChoice aggregateChoice, EncryptedValueWithProofs value, int weight)
    {
        if (weight > 1)
        {
            // A ballot weight is a small public integer, not a nonce, so it is raised with a
            // window that walks only the weight's own bits rather than the full width of Z_q.
            aggregateChoice.AProduct.MultiplyPower(value.Alpha, weight);
            aggregateChoice.BProduct.MultiplyPower(value.Beta, weight);
        }
        else
        {
            aggregateChoice.AProduct.Multiply(value.Alpha);
            aggregateChoice.BProduct.Multiply(value.Beta);
        }
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
            () => new EncryptedTally(_manifest, _allowAvx512),
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
            () => pool.TryTake(out var partial) ? partial : new EncryptedTally(_manifest, _allowAvx512),
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
            }
        });

        foreach (var (contestId, contest) in Contests)
        {
            foreach (var partial in partials)
            {
                contest.CastWeight += partial.Contests[contestId].CastWeight;
            }
        }

        BallotsCast += partials.Sum(partial => partial.BallotsCast);
        TotalCastWeight += partials.Sum(partial => partial.TotalCastWeight);
    }

    /// <summary>
    /// The most one cast ballot of weight 1 can add to the count of <paramref name="field"/>, a
    /// verifiable field of <paramref name="contest"/>:
    /// <list type="bullet">
    /// <item>A selectable option takes at most R = <see cref="Contest.OptionSelectionLimit"/>
    /// (§3.3.7) and all options together at most L = <see cref="Contest.SelectionLimit"/>, so
    /// min(R, L). A sum above L, or one option above R, is an overvote, which the encryptor turns
    /// into all zeros (§3.3.5); with L = 1 and R = 2, say, a 2 is an overvote and the bound is 1.
    /// A ballot whose option exceeds min(R, L) cannot carry a valid selection-limit proof.</item>
    /// <item>A supplemental field takes at most its range bound (§3.3.9): 1 for an indicator, L for
    /// the undervote difference count, the number of write-in fields for the write-in count.</item>
    /// </list>
    /// </summary>
    internal static int MaximumOptionValue(Contest contest, Choice field)
    {
        return field is SupplementalField
            ? Math.Max(0, contest.RangeBound(field))
            : Math.Max(0, Math.Min(contest.OptionSelectionLimit, contest.SelectionLimit));
    }

    public class EncryptedAggregateContest
    {
        public required string ContestId { get; init; }

        /// <summary>
        /// One aggregate per verifiable field, keyed by label: the selectable options and the
        /// supplemental fields the manifest declares for the contest.
        /// </summary>
        public required Dictionary<string, EncryptedAggregateChoice> Choices { get; init; }

        /// <summary>
        /// The sum of the weights W (eq. 80) of the cast ballots added that list this contest: every
        /// such ballot lists every option and declared field of the contest (BallotStructure), so
        /// this times a field's <see cref="EncryptedAggregateChoice.MaximumValue"/> bounds its count
        /// (<see cref="EncryptedAggregateChoice.MaximumCount"/>). Ballots of a style without the
        /// contest add nothing. Not part of 9.A/9.B; published with the tally so that a tally read
        /// back from a record can be decrypted, and compared with the recomputed weight by
        /// Verification 9 ("9.structure"), so that a published weight cannot widen (or narrow) the
        /// administrator's search.
        /// </summary>
        public long CastWeight { get; internal set; }
    }

    public class EncryptedAggregateChoice
    {
        public required string ChoiceId { get; init; }

        /// <summary>The most one cast ballot of weight 1 adds to this count; see <see cref="EncryptedTally.MaximumOptionValue"/>.</summary>
        internal int MaximumValue { get; init; }

        /// <summary>The contest aggregate this choice belongs to, whose cast weight bounds its count. Null on an aggregate built outside the tally.</summary>
        internal EncryptedAggregateContest? Contest { get; init; }

        /// <summary>
        /// The largest count this choice's aggregate can encrypt: the sum, over the cast ballots added,
        /// of the ballot's weight W (eq. 80) times the most one ballot can give the option or field
        /// (<see cref="MaximumValue"/>: min(R, L) for an option; 1, L or the number of write-in
        /// fields for a supplemental field), that is its contest's
        /// <see cref="EncryptedAggregateContest.CastWeight"/> times <see cref="MaximumValue"/>. Tally
        /// decryption searches [0, this] for the count (§3.6.2); the number of ballots cast, which it
        /// used to search, is too small once a weight or R exceeds 1 (G16). A tally read back from a
        /// record (<see cref="Serialization.JsonElectionRecordSerializer"/>) restores it from the
        /// published cast weight and the manifest (S10a); Verification 9 checks that weight. An
        /// aggregate built outside the tally has 0 here, so decrypting it fails closed for any
        /// nonzero count. The product saturates at <see cref="long.MaxValue"/> rather than wrapping,
        /// so a forged cast weight read from a record cannot turn the bound negative; decryption
        /// then refuses it as beyond its search (<see cref="TallyDecryptionException"/>).
        /// </summary>
        public long MaximumCount
        {
            get
            {
                long castWeight = Contest?.CastWeight ?? 0;
                return MaximumValue != 0 && castWeight > long.MaxValue / MaximumValue
                    ? long.MaxValue
                    : castWeight * MaximumValue;
            }
        }

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

        internal ModPProduct AProduct { get; private set; } = new(1);

        internal ModPProduct BProduct { get; private set; } = new(1);

        /// <summary>
        /// A test seam: true keeps both running products on the scalar Montgomery engine even where
        /// AVX-512F is available (<see cref="EncryptedTally(Manifest, bool)"/>). Set before
        /// <see cref="A"/> and <see cref="B"/> in an initializer.
        /// </summary>
        internal bool ScalarEngine
        {
            init
            {
                if (value)
                {
                    AProduct = new ModPProduct(1, allowAvx512: false);
                    BProduct = new ModPProduct(1, allowAvx512: false);
                }
            }
        }

        public bool IsZero()
        {
            return A == 1 && B == 1;
        }
    }
}
