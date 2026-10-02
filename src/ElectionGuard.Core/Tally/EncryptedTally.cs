using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
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

    public void AddBallot(EncryptedBallot encryptedBallot)
    {
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

        // Merging under the lock above serialized a multiply per choice per worker, which on many
        // cores cost more than the aggregation itself. Merged choice by choice instead, each
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
