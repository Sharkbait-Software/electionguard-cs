using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.Verify.KeyGeneration;

/// <summary>
/// Verification 3 (Election public-key validation)
/// </summary>
public class ElectionPublicKeyVerification
{
    public void Verify(List<GuardianPublicView> guardians, ElectionPublicKeys electionPublicKeys)
    {
        // K and K-hat are products over i = 1..n (eqs. 25, 26). Over a short, padded or duplicated
        // guardian list they can still be computed consistently, so the set itself is checked
        // first: a ceremony run with fewer guardians than H_P claims would otherwise pass while
        // silently changing the threshold. It is reported under 3.A, the first product that
        // cannot be formed.
        GuardianSet.RequireComplete(guardians, "3.A");

        foreach (var guardian in guardians)
        {
            if (guardian.VoteEncryptionCommitments.Count == 0)
            {
                throw new VerificationFailedException("3.A", $"Guardian {guardian.Index.Index} has no vote encryption public key K_i.");
            }

            if (guardian.OtherBallotDataEncryptionCommitments.Count == 0)
            {
                throw new VerificationFailedException("3.B", $"Guardian {guardian.Index.Index} has no ballot data encryption public key K-hat_i.");
            }
        }

        // 3.A
        Verify("3.A", guardians.Select(x => x.VoteEncryptionCommitments[0]).ToList(), electionPublicKeys.VoteEncryptionKey);

        // 3.B
        Verify("3.B", guardians.Select(x => x.OtherBallotDataEncryptionCommitments[0]).ToList(), electionPublicKeys.OtherBallotDataEncryptionKey);
    }

    private void Verify(string subSection, List<IntegerModP> guardianPublicKeys, IntegerModP electionPublicKey)
    {
        IntegerModP result = guardianPublicKeys[0];

        for (int i = 1; i < guardianPublicKeys.Count; i++)
        {
            result = result * guardianPublicKeys[i];
        }

        if (result != electionPublicKey)
        {
            throw new VerificationFailedException(subSection, $"Election public key verification failed. Expected: {electionPublicKey} Actual: {result}");
        }
    }
}
