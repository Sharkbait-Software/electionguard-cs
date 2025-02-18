using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.Verify;

public class ExtendedBaseHashVerification
{
    public void Verify(ExtendedBaseHash actual, ElectionBaseHash baseHash, ElectionPublicKeys electionPublicKeys)
    {
        var expected = EGHash.Hash(baseHash,
            [0x14],
            electionPublicKeys.VoteEncryptionKey,
            electionPublicKeys.OtherBallotDataEncryptionKey);

        if (expected != (byte[])actual)
        {
            throw new VerificationFailedException("4.A", "Extended base hash was not calculated correctly.");
        }
    }
}
