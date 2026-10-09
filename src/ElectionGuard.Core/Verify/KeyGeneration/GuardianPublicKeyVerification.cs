using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using System.Numerics;
using ElectionGuard.Core.RecordFormat;

namespace ElectionGuard.Core.Verify.KeyGeneration;

/// <summary>
/// Verification 2 (Guardian public-key validation)
/// </summary>
public class GuardianPublicKeyVerification
{
    /// <summary>
    /// Verification 2 on an item decoded from the election record (design §4.8): a commitment or κ_i ≥ p fails 2.A, a response ≥ q 2.B and a challenge ≥ q 2.C, then
    /// <see cref="RecordItemNotEvaluableException"/> if another verification's range finding is on an
    /// item it reads, then <see cref="Verify(IEnumerable{GuardianPublicView})"/>. See <see cref="RecordItemGate"/>.
    /// </summary>
    internal void Verify(RecordDecoded<RecordSetup> setup)
    {
        Verify(RecordItemGate.Require(setup, 2, ElectionGuard.Core.RecordFormat.Mappers.SetupMapper.ReadByVerification2).Guardians);
    }

    /// <summary>
    /// Verification 2 over the whole guardian set: "for each guardian G_i, 1 &lt;= i &lt;= n". The set
    /// must be exactly G_1..G_n, so a missing, extra or duplicated guardian fails rather than being
    /// skipped. The spec letters no separate check for this; it is reported under 2.A, the first
    /// confirmation that cannot be made for a guardian that is missing.
    /// </summary>
    public void Verify(IEnumerable<GuardianPublicView> guardians)
    {
        var guardianList = guardians.ToList();

        GuardianSet.RequireComplete(guardianList, "2.A");

        foreach (var guardian in guardianList)
        {
            Verify(guardian);
        }
    }

    public void Verify(GuardianPublicView guardian)
    {
        int k = EGParameters.GuardianParameters.K;

        // Shape first, before 2.1-2.4 index into the lists. The proof is over exactly
        // K_{i,0..k-1} (and K-hat_{i,0..k-1}) and kappa_i, with responses v_{i,0..k} (eqs. 11, 13):
        // an extra commitment K_{i,k} would be published without a proof, hashed into no challenge,
        // and yet raise the degree of the guardian's polynomial, and so the decryption threshold.
        // 2.A confirms "the values K_{i,j} and K-hat_{i,j}, for 0 <= j < k", so a list of any other
        // length fails 2.A; 2.B confirms "the values v_{i,j} and v-hat_{i,j}, for 0 <= j <= k", so a
        // response list of any length but k + 1 fails 2.B.
        RequireCount("2.A", guardian, "vote encryption commitments K_i,j", guardian.VoteEncryptionCommitments.Count, k);
        RequireCount("2.A", guardian, "ballot data encryption commitments K-hat_i,j", guardian.OtherBallotDataEncryptionCommitments.Count, k);
        RequireCount("2.B", guardian, "vote encryption proof responses v_i,j", guardian.VoteEncryptionProof.Responses.Length, k + 1);
        RequireCount("2.B", guardian, "ballot data encryption proof responses v-hat_i,j", guardian.OtherDataEncryptionProof.Responses.Length, k + 1);

        List<IntegerModP> voteEncryptionHValues = new List<IntegerModP>();
        List<IntegerModP> otherBallotDataEncryptionHValues = new List<IntegerModP>();

        // 2.1
        for (int j = 0; j < k; j++)
        {
            IntegerModP hij = MontgomeryModP.PowModP(EGParameters.G, guardian.VoteEncryptionProof.Responses[j]) * MontgomeryModP.PowModP(guardian.VoteEncryptionCommitments[j], guardian.VoteEncryptionProof.Challenge);
            voteEncryptionHValues.Add(hij);
        }

        // 2.2
        IntegerModP hik = MontgomeryModP.PowModP(EGParameters.G, guardian.VoteEncryptionProof.Responses[k]) * MontgomeryModP.PowModP(guardian.CommunicationPublicKey, guardian.VoteEncryptionProof.Challenge);
        voteEncryptionHValues.Add(hik);

        // 2.3
        for (int j = 0; j < k; j++)
        {
            IntegerModP hHatij = MontgomeryModP.PowModP(EGParameters.G, guardian.OtherDataEncryptionProof.Responses[j]) * MontgomeryModP.PowModP(guardian.OtherBallotDataEncryptionCommitments[j], guardian.OtherDataEncryptionProof.Challenge);
            otherBallotDataEncryptionHValues.Add(hHatij);
        }

        // 2.4
        IntegerModP hHatik = MontgomeryModP.PowModP(EGParameters.G, guardian.OtherDataEncryptionProof.Responses[k]) * MontgomeryModP.PowModP(guardian.CommunicationPublicKey, guardian.OtherDataEncryptionProof.Challenge);
        otherBallotDataEncryptionHValues.Add(hHatik);

        // 2.A
        for (int j = 0; j < k; j++)
        {
            if (MontgomeryModP.PowModP(guardian.VoteEncryptionCommitments[j], EGParameters.Q) != new BigInteger(1))
            {
                throw new VerificationFailedException("2.A", "Public commitment is not valid.");
            }
        }

        for (int j = 0; j < k; j++)
        {
            if (MontgomeryModP.PowModP(guardian.OtherBallotDataEncryptionCommitments[j], EGParameters.Q) != new BigInteger(1))
            {
                throw new VerificationFailedException("2.A", "Public commitment is not valid.");
            }
        }

        if (MontgomeryModP.PowModP(guardian.CommunicationPublicKey, EGParameters.Q) != new BigInteger(1))
        {
            throw new VerificationFailedException("2.A", "Communication public key is not valid.");
        }

        // 2.B: there are exactly k + 1 responses in each proof (checked above). That each one is in
        // Z_q, 0 <= v < q, holds by construction: IntegerModQ reduces mod q. Rejecting an
        // out-of-range encoding before it is reduced is a parsing concern (audit G23, stage S3).

        // 2.C: exactly the inputs of eqs. (11) and (13): K_{i,0..k-1}, kappa_i, h_{i,0..k}.
        List<byte[]> cBytes = [
            [0x10],
            System.Text.Encoding.UTF8.GetBytes("pk_vote"),
            guardian.Index,
        ];
        for (int j = 0; j < k; j++)
        {
            cBytes.Add(guardian.VoteEncryptionCommitments[j]);
        }
        cBytes.Add(guardian.CommunicationPublicKey);
        cBytes.AddRange(voteEncryptionHValues.Select(h => h.ToByteArray()));

        IntegerModQ ci = EGHash.HashModQ(EGParameters.ParameterBaseHash, cBytes.ToArray());
        if (ci != guardian.VoteEncryptionProof.Challenge)
        {
            throw new VerificationFailedException("2.C", "Challenge value Ci was not computed correctly.");
        }

        List<byte[]> cHatBytes = [
            [0x10],
            System.Text.Encoding.UTF8.GetBytes("pk_data"),
            guardian.Index,
        ];
        for (int j = 0; j < k; j++)
        {
            cHatBytes.Add(guardian.OtherBallotDataEncryptionCommitments[j]);
        }
        cHatBytes.Add(guardian.CommunicationPublicKey);
        cHatBytes.AddRange(otherBallotDataEncryptionHValues.Select(h => h.ToByteArray()));

        IntegerModQ cHati = EGHash.HashModQ(EGParameters.ParameterBaseHash, cHatBytes.ToArray());
        if (cHati != guardian.OtherDataEncryptionProof.Challenge)
        {
            throw new VerificationFailedException("2.C", "Challenge value CHati was not computed correctly.");
        }
    }

    private static void RequireCount(string subSection, GuardianPublicView guardian, string what, int actual, int expected)
    {
        if (actual != expected)
        {
            throw new VerificationFailedException(subSection, $"Guardian {guardian.Index.Index} publishes {actual} {what}; exactly {expected} are required.");
        }
    }
}
