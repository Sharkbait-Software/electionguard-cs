using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;

namespace ElectionGuard.Core.Tally;

public class TallyGuardian
{
    public TallyGuardian(GuardianSecretShares shares)
    {
        _shares = shares;
    }

    private readonly GuardianSecretShares _shares;

    //public PartialDecryption Decrypt(EncryptedTally encryptedTally)
    //{
    //    foreach(var contest in encryptedTally.Contests)
    //    {
    //        foreach(var choice in contest.Value.Choices)
    //        {
    //            var mi = IntegerModP.PowModP(choice.Value.A, _shares.VoteEncryptionKeyShare);
    //        }
    //    }
    //}
}
