using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.Verify;

/// <summary>
/// Verification 3 (Election public-key validation)
/// </summary>
public class ElectionPublicKeyVerification
{
    public void Verify(List<GuardianPublicView> guardians, ElectionPublicKeys electionPublicKeys)
    {
        // 3.A
        Verify("3.A", guardians.SelectMany(x => x.VoteEncryptionCommitments).ToList(), electionPublicKeys.VoteEncryptionKey);

        // 3.B
        Verify("3.B", guardians.SelectMany(x => x.OtherBallotDataEncryptionCommitments).ToList(), electionPublicKeys.OtherBallotDataEncryptionKey);
    }

    private void Verify(string subSection, List<IntegerModP> guardianPublicKeys, IntegerModP electionPublicKey)
    {
        IntegerModP result = guardianPublicKeys[0];

        for(int i = 1; i < guardianPublicKeys.Count; i++)
        {
            result = result * guardianPublicKeys[i];
        }

        if (result != electionPublicKey)
        {
            throw new VerificationFailedException(subSection, $"Election public key verification failed. Expected: {electionPublicKey} Actual: {result}");
        }
    }
}
