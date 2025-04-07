using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.Verify.KeyGeneration;

/// <summary>
/// Verification 2 (Guardian public-key validation)
/// </summary>
public class GuardianPublicKeyVerification
{
    public void Verify(IEnumerable<GuardianPublicView> guardians)
    {
        foreach (var guardian in guardians)
        {
            Verify(guardian);
        }
    }

    public void Verify(GuardianPublicView guardian)
    {
        List<IntegerModP> voteEncryptionHValues = new List<IntegerModP>();
        List<IntegerModP> otherBallotDataEncryptionHValues = new List<IntegerModP>();

        // 2.1
        for (int j = 0; j < EGParameters.GuardianParameters.K; j++)
        {
            IntegerModP hij = IntegerModP.PowModP(EGParameters.CryptographicParameters.G, guardian.VoteEncryptionProof.Responses[j]) * IntegerModP.PowModP(guardian.VoteEncryptionCommitments[j], guardian.VoteEncryptionProof.Challenge);
            voteEncryptionHValues.Add(hij);
        }

        // 2.2
        IntegerModP hik = IntegerModP.PowModP(EGParameters.CryptographicParameters.G, guardian.VoteEncryptionProof.Responses[EGParameters.GuardianParameters.K]) * IntegerModP.PowModP(guardian.CommunicationPublicKey, guardian.VoteEncryptionProof.Challenge);
        voteEncryptionHValues.Add(hik);

        // 2.3
        for (int j = 0; j < EGParameters.GuardianParameters.K; j++)
        {
            IntegerModP hHatij = IntegerModP.PowModP(EGParameters.CryptographicParameters.G, guardian.OtherDataEncryptionProof.Responses[j]) * IntegerModP.PowModP(guardian.OtherBallotDataEncryptionCommitments[j], guardian.OtherDataEncryptionProof.Challenge);
            otherBallotDataEncryptionHValues.Add(hHatij);
        }

        // 2.2
        IntegerModP hHatik = IntegerModP.PowModP(EGParameters.CryptographicParameters.G, guardian.OtherDataEncryptionProof.Responses[EGParameters.GuardianParameters.K]) * IntegerModP.PowModP(guardian.CommunicationPublicKey, guardian.OtherDataEncryptionProof.Challenge);
        otherBallotDataEncryptionHValues.Add(hHatik);

        // 2.A
        for (int j = 0; j < EGParameters.GuardianParameters.K; j++)
        {
            if (IntegerModP.PowModP(guardian.VoteEncryptionCommitments[j], EGParameters.CryptographicParameters.Q) != new BigInteger(1))
            {
                throw new VerificationFailedException("2.A", "Public commitment is not valid.");
            }
        }

        for (int j = 0; j < EGParameters.GuardianParameters.K; j++)
        {
            if (IntegerModP.PowModP(guardian.OtherBallotDataEncryptionCommitments[j], EGParameters.CryptographicParameters.Q) != new BigInteger(1))
            {
                throw new VerificationFailedException("2.A", "Public commitment is not valid.");
            }
        }

        if (IntegerModP.PowModP(guardian.CommunicationPublicKey, EGParameters.CryptographicParameters.Q) != new BigInteger(1))
        {
            throw new VerificationFailedException("2.A", "Communication public key is not valid.");
        }

        // 2.B
        for (int j = 0; j <= guardian.VoteEncryptionProof.Responses.Length; j++)
        {
            // Because all objects are already IntegerModQ, this is already true for the time being.
        }

        // 2.C
        List<byte[]> cBytes = [
            [0x10],
            System.Text.Encoding.UTF8.GetBytes("pk_vote"),
            guardian.Index,
        ];
        cBytes.AddRange(guardian.VoteEncryptionCommitments.Select(c => c.ToByteArray()));
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
        cHatBytes.AddRange(guardian.OtherBallotDataEncryptionCommitments.Select(c => c.ToByteArray()));
        cHatBytes.Add(guardian.CommunicationPublicKey);
        cHatBytes.AddRange(otherBallotDataEncryptionHValues.Select(h => h.ToByteArray()));

        IntegerModQ cHati = EGHash.HashModQ(EGParameters.ParameterBaseHash, cHatBytes.ToArray());
        if (cHati != guardian.OtherDataEncryptionProof.Challenge)
        {
            throw new VerificationFailedException("2.C", "Challenge value CHati was not computed correctly.");
        }
    }
}