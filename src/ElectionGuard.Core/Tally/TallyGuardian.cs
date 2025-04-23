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

    public PartialTallyDecryption Decrypt(EncryptedTally encryptedTally)
    {
        var partialTally = new PartialTallyDecryption
        {
            GuardianIndex = _index,
            Contests = new Dictionary<string, PartialTallyContestDecryption>(),
        };

        foreach (var contest in encryptedTally.Contests)
        {
            var partialContest = new PartialTallyContestDecryption
            {
                Choices = new Dictionary<string, PartialTallyChoiceDecryption>(),
            };
            partialTally.Contests[contest.Key] = partialContest;

            foreach (var choice in contest.Value.Choices)
            {
                var mi = IntegerModP.PowModP(choice.Value.A, _shares.VoteEncryptionKeyShare);
                partialContest.Choices[choice.Key] = new PartialTallyChoiceDecryption
                {
                    Mi = mi,
                };
            }
        }

        return partialTally;
    }
}

public class TallyAdmin
{
    public DecryptedTally Decrypt(List<PartialTallyDecryption> partialDecryptions, EncryptedTally encryptedTally, ElectionPublicKeys publicKeys)
    {
        var decryptedTally = new DecryptedTally
        {
            Contests = new Dictionary<string, DecryptedContest>(),
        };
        partialDecryptions = partialDecryptions.OrderBy(x => x.GuardianIndex.Index).ToList();

        var availableGuardians = partialDecryptions.Select(x => x.GuardianIndex).ToList();
        List<IntegerModQ> lagrangeCoefficients = new List<IntegerModQ>();
        for (int i = 0; i < partialDecryptions.Count; i++)
        {
            var coefficient = CalculateLagrangeCoefficient(partialDecryptions[i].GuardianIndex, availableGuardians);
            lagrangeCoefficients.Add(coefficient);
        }

        foreach (var contest in partialDecryptions[0].Contests)
        {
            var decryptedContest = new DecryptedContest
            {
                Choices = new Dictionary<string, DecryptedChoice>(),
            };
            decryptedTally.Contests[contest.Key] = decryptedContest;

            foreach (var choice in contest.Value.Choices)
            {
                List<IntegerModP> mValues = new List<IntegerModP>();
                for (int i = 0; i < lagrangeCoefficients.Count; i++)
                {
                    var partialContest = partialDecryptions[i].Contests[contest.Key];
                    var partialChoice = partialContest.Choices[choice.Key];

                    var miwi = IntegerModP.PowModP(partialChoice.Mi, lagrangeCoefficients[i]);
                    mValues.Add(miwi);
                }

                var m = mValues.Product();
                var encryptedChoice = encryptedTally.Contests[contest.Key].Choices[choice.Key];
                var t = encryptedChoice.B * IntegerModP.PowModP(m, -1);

                int result = -1;
                for (int i = 0; i <= encryptedTally.BallotsCast; i++)
                {
                    var maybeT = IntegerModP.PowModP(publicKeys.VoteEncryptionKey, i);
                    if (maybeT == t)
                    {
                        result = i;
                    }
                }

                if (result == -1)
                {
                    throw new Exception($"Tally did not decrypt successfully.");
                }

                var decryptedChoice = new DecryptedChoice
                {
                    VoteCount = result,
                };
                decryptedContest.Choices[choice.Key] = decryptedChoice;
            }
        }

        return decryptedTally;
    }

    private IntegerModQ CalculateLagrangeCoefficient(GuardianIndex i, IEnumerable<GuardianIndex> availableGuardians)
    {
        List<IntegerModQ> prod = new List<IntegerModQ>();

        // Because this equation can yield intermediate fractions that eventually resolve to integers,
        // we don't want to keep the intermediate types as IntegerModQ.
        // Therefore, we're going to use an alternate representation of the math:
        // prod(l) / prod(l - i);

        var ls = availableGuardians.Where(x => x != i).Select(x => x.Index);
        var prodL = ls.Product();
        var prodLMinusI = ls.Select(x => x - i.Index).Product();
        
        var wi = prodL / prodLMinusI;
        return wi;

        //foreach (var l in availableGuardians.Where(x => x != i))
        //{
        //    var p = l / (l - i);
        //    prod.Add(p);
        //}

        //var wi = prod.Product();
        //return wi;
    }
}