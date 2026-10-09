using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;

namespace ElectionGuard.Core.Verify.KeyGeneration;

/// <summary>
/// Verification 3 (Election public-key validation)
/// </summary>
public class ElectionPublicKeyVerification
{
    /// <summary>
    /// Verification 3 on an item decoded from the election record (design §4.8): K ≥ p fails 3.A and K-hat ≥ p 3.B (each is an equality with a product reduced mod p, so it can never hold), then
    /// <see cref="RecordItemNotEvaluableException"/> if another verification's range finding is on an
    /// item it reads, then <see cref="Verify(List{GuardianPublicView}, ElectionPublicKeys)"/>. See <see cref="RecordItemGate"/>.
    /// </summary>
    internal void Verify(RecordDecoded<RecordSetup> setup)
    {
        var value = RecordItemGate.Require(setup, 3, ElectionGuard.Core.RecordFormat.Mappers.SetupMapper.ReadByVerification3);
        Verify([.. value.Guardians], value.Keys);
    }

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
