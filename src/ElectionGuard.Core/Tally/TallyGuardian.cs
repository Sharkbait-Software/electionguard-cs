using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using static ElectionGuard.Core.Tally.DecryptedTally;
using static ElectionGuard.Core.Tally.PartialTallyDecryption;

namespace ElectionGuard.Core.Tally;

public class TallyGuardian
{
    public TallyGuardian(GuardianIndex index, GuardianSecretShares shares)
    {
        _index = index;
        _shares = shares;
    }

    private readonly GuardianIndex _index;
    private readonly GuardianSecretShares _shares;

    /// <summary>
    /// This guardian's partial decryption M_i = A^s_i of every aggregate choice, computed on up to
    /// <paramref name="maxDegreeOfParallelism"/> threads (-1, the default, for no limit). Each
    /// choice's exponentiation is independent of every other's.
    /// </summary>
    public PartialTallyDecryption Decrypt(EncryptedTally encryptedTally, int maxDegreeOfParallelism = -1)
    {
        var choices = AggregateChoices(encryptedTally);
        var shares = new IntegerModP[choices.Length];
        Parallel.For(0, choices.Length, new ParallelOptions { MaxDegreeOfParallelism = maxDegreeOfParallelism }, i =>
        {
            shares[i] = MontgomeryModP.PowModP(choices[i].Aggregate.A, _shares.VoteEncryptionKeyShare);
        });

        var partialTally = new PartialTallyDecryption
        {
            GuardianIndex = _index,
            Contests = new Dictionary<string, PartialTallyContestDecryption>(),
        };

        for (int i = 0; i < choices.Length; i++)
        {
            if (!partialTally.Contests.TryGetValue(choices[i].ContestId, out var partialContest))
            {
                partialContest = new PartialTallyContestDecryption
                {
                    Choices = new Dictionary<string, PartialTallyChoiceDecryption>(),
                };
                partialTally.Contests[choices[i].ContestId] = partialContest;
            }

            partialContest.Choices[choices[i].ChoiceId] = new PartialTallyChoiceDecryption
            {
                Mi = shares[i],
            };
        }

        return partialTally;
    }

    /// <summary>Every aggregate choice of the tally, contest by contest, in the tally's own order.</summary>
    internal static (string ContestId, string ChoiceId, EncryptedTally.EncryptedAggregateChoice Aggregate)[] AggregateChoices(EncryptedTally encryptedTally)
    {
        return encryptedTally.Contests
            .SelectMany(contest => contest.Value.Choices.Select(choice => (contest.Key, choice.Key, choice.Value)))
            .ToArray();
    }
}

public class TallyAdmin
{
    /// <summary>
    /// Combines threshold-many partial decryptions into the decrypted tally (§3.6), working on up to
    /// <paramref name="maxDegreeOfParallelism"/> threads (-1, the default, for no limit).
    /// </summary>
    public DecryptedTally Decrypt(List<PartialTallyDecryption> partialDecryptions, EncryptedTally encryptedTally, ElectionPublicKeys publicKeys, int maxDegreeOfParallelism = -1)
    {
        partialDecryptions = partialDecryptions.OrderBy(x => x.GuardianIndex.Index).ToList();

        var availableGuardians = partialDecryptions.Select(x => x.GuardianIndex).ToList();
        Dictionary<GuardianIndex, IntegerModQ> lagrangeCoefficients = new Dictionary<GuardianIndex, IntegerModQ>();
        for (int i = 0; i < partialDecryptions.Count; i++)
        {
            var coefficient = CalculateLagrangeCoefficient(partialDecryptions[i].GuardianIndex, availableGuardians);
            lagrangeCoefficients[partialDecryptions[i].GuardianIndex] = coefficient;
        }

        var choices = TallyGuardian.AggregateChoices(encryptedTally);
        var options = new ParallelOptions { MaxDegreeOfParallelism = maxDegreeOfParallelism };

        // M = prod M_i^w_i for every choice. These exponentiations are most of what is left of
        // decryption, and every choice's are independent of every other's.
        var combined = new IntegerModP[choices.Length];
        Parallel.For(0, choices.Length, options, c =>
        {
            IntegerModP m = 1;
            foreach (var partialDecryption in partialDecryptions)
            {
                var partialChoice = partialDecryption.Contests[choices[c].ContestId].Choices[choices[c].ChoiceId];
                var lagrangeCoefficient = lagrangeCoefficients[partialDecryption.GuardianIndex];
                m *= MontgomeryModP.PowModP(partialChoice.Mi, lagrangeCoefficient);
            }

            combined[c] = m;
        });

        // T = B / M. A zero M, which only a corrupt share can produce, has no inverse and no count
        // to recover.
        if (combined.Any(m => m == 0))
        {
            throw new Exception($"Tally did not decrypt successfully.");
        }

        var inverses = InvertAll(combined);

        // One table for every choice: each count lies in [0, BallotsCast], and K is the same base
        // throughout. See BoundedDiscreteLog for why this replaced trying every candidate. The count
        // is published once decrypted, so the variable-time search, which stops as soon as it finds
        // it, gives nothing away.
        var discreteLog = new BoundedDiscreteLog(publicKeys.VoteEncryptionKey, encryptedTally.BallotsCast, choices.Length);
        var counts = new int[choices.Length];
        int failures = 0;
        Parallel.For(0, choices.Length, options, c =>
        {
            var t = choices[c].Aggregate.B * inverses[c];
            if (!discreteLog.TryFind(t, out counts[c]))
            {
                Interlocked.Increment(ref failures);
            }
        });

        // Thrown here rather than inside the loop, where Parallel.For would wrap it in an
        // AggregateException.
        if (failures > 0)
        {
            throw new Exception($"Tally did not decrypt successfully.");
        }

        var decryptedTally = new DecryptedTally
        {
            Contests = new Dictionary<string, DecryptedContest>(),
        };

        for (int c = 0; c < choices.Length; c++)
        {
            if (!decryptedTally.Contests.TryGetValue(choices[c].ContestId, out var decryptedContest))
            {
                decryptedContest = new DecryptedContest
                {
                    Choices = new Dictionary<string, DecryptedChoice>(),
                };
                decryptedTally.Contests[choices[c].ContestId] = decryptedContest;
            }

            decryptedContest.Choices[choices[c].ChoiceId] = new DecryptedChoice
            {
                VoteCount = counts[c],
            };
        }

        return decryptedTally;
    }

    /// <summary>
    /// The inverse of every value, all nonzero, for the price of one inversion and three
    /// multiplications per value (Montgomery's trick): invert the product of them all, then peel
    /// each value's inverse off it from the back. A Euclidean inversion of a 4096-bit residue costs
    /// about as much as 25 multiplications and allocates a BigInteger per division step, so inverting
    /// each choice separately allocated more than the rest of decryption put together.
    ///
    /// The values are combined partial decryptions, which are published, so the variable-time
    /// inversion is safe here.
    /// </summary>
    internal static IntegerModP[] InvertAll(IntegerModP[] values)
    {
        var inverses = new IntegerModP[values.Length];
        if (values.Length == 0)
        {
            return inverses;
        }

        // prefix[i] = values[0] * ... * values[i].
        var prefix = new IntegerModP[values.Length];
        prefix[0] = values[0];
        for (int i = 1; i < values.Length; i++)
        {
            prefix[i] = prefix[i - 1] * values[i];
        }

        // Invariant at the top of each iteration: remaining = (values[0] * ... * values[i])^-1.
        var remaining = new IntegerModP(prefix[^1].ToBigInteger().ModInverseVariableTime(EGParameters.P));
        for (int i = values.Length - 1; i > 0; i--)
        {
            inverses[i] = remaining * prefix[i - 1];
            remaining *= values[i];
        }

        inverses[0] = remaining;
        return inverses;
    }

    private IntegerModQ CalculateLagrangeCoefficient(GuardianIndex i, IEnumerable<GuardianIndex> availableGuardians)
    {
        var ls = availableGuardians.Where(x => x != i).ToList();

        var prodL = ls.Select(x => new IntegerModQ(x.Index)).Product();
        var prodLMinusI = ls.Select(x => new IntegerModQ(x.Index - i.Index)).Product();

        return prodL / prodLMinusI;
    }
}