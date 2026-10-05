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
    public int BallotsCast { get; private set; } = 0;

    /// <summary>
    /// Multiplies <paramref name="encryptedBallot"/>'s ciphertexts into the aggregate. A ballot that
    /// does not list exactly its ballot style's contests and the manifest's options, each once, is
    /// rejected before anything is multiplied in, with a <see cref="VerificationFailedException"/> of
    /// sub-section "9.structure" (Verification 9 recomputes the aggregate through this method; see
    /// <see cref="BallotStructure"/>). Otherwise a contest or option listed twice would count twice.
    /// </summary>
    public void AddBallot(EncryptedBallot encryptedBallot)
    {
        BallotStructure.Require(encryptedBallot, _manifest, 9);

        foreach(var contest in encryptedBallot.Contests)
        {
            var aggregateContest = Contests[contest.Id];
            foreach(var choice in contest.Choices)
            {
                var aggregateChoice = aggregateContest.Choices[choice.ChoiceId];

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
            }
        });

        BallotsCast += partials.Sum(partial => partial.BallotsCast);
    }

    public class EncryptedAggregateContest
    {
        public required string ContestId { get; init; }
        public required Dictionary<string, EncryptedAggregateChoice> Choices { get; init; }
    }

    public class EncryptedAggregateChoice
    {
        public required string ChoiceId { get; init; }

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
