using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.Verify.Ballot;

/// <summary>
/// Verification 7 (Adherence to vote limits)
/// </summary>
public class AdherenceToVoteLimitsVerification
{
    public void Verify(EncryptedBallot encryptedBallot, EncryptionRecord encryptionRecord)
    {
        foreach (var contest in encryptedBallot.Contests)
        {
            var manifestContest = encryptionRecord.Manifest.Contests.Single(x => x.Id == contest.Id);
            Verify(contest, manifestContest, encryptionRecord, encryptedBallot);
        }
    }

    private void Verify(EncryptedContest encryptedContest, Contest contest, EncryptionRecord encryptionRecord, EncryptedBallot encryptedBallot)
    {
        if (encryptedContest.Proofs.Length != contest.SelectionLimit)
        {
            throw new VerificationFailedException("7", $"A challenge/response value was not provided for all possible values of the contest selection limit of {contest.SelectionLimit}.");
        }

        var alpha = encryptedContest.Choices.Select(x => x.Alpha).Product();
        var beta = encryptedContest.Choices.Select(x => x.Beta).Product();

        List<(IntegerModP a, IntegerModP b)> calculatedValues = new();
        for (int i = 0; i < encryptedContest.Proofs.Length; i++)
        {
            var crPair = encryptedContest.Proofs[i];

            VerifyIsInZq(crPair.Challenge, encryptionRecord.CryptographicParameters);
            VerifyIsInZq(crPair.Response, encryptionRecord.CryptographicParameters);

            var a = IntegerModP.PowModP(encryptionRecord.CryptographicParameters.G, crPair.Response)
                * IntegerModP.PowModP(alpha, crPair.Challenge);
            var w = crPair.Response - i * crPair.Challenge;
            var b = IntegerModP.PowModP(encryptionRecord.ElectionPublicKeys.VoteEncryptionKey, w)
                * IntegerModP.PowModP(beta, crPair.Challenge);
            calculatedValues.Add((a, b));
        }

        List<byte[]> bytesToHash = [
                [0x24],
                contest.Index.ToByteArray(),
                alpha,
                beta];
        foreach (var val in calculatedValues)
        {
            bytesToHash.Add(val.a);
            bytesToHash.Add(val.b);
        }

        var c = EGHash.HashModQ(encryptedBallot.SelectionEncryptionIdentifierHash, bytesToHash.ToArray());

        VerifyIsInZpr(alpha, encryptionRecord.CryptographicParameters);
        VerifyIsInZpr(beta, encryptionRecord.CryptographicParameters);

        var sumC = encryptedContest.Proofs.Select(x => x.Challenge).Sum();
        if (sumC != c)
        {
            throw new VerificationFailedException("7.D", "Sum of challenge values did not equal c.");
        }
    }

    private void VerifyIsInZpr(IntegerModP value, CryptographicParameters cryptographicParameters)
    {
        // 6.A
        if (value <= 0
            || value > cryptographicParameters.P
            || IntegerModP.PowModP(value, cryptographicParameters.Q) != 1)
        {
            throw new VerificationFailedException("7.A", "Value was not in Zpr.");
        }
    }

    private void VerifyIsInZq(IntegerModQ value, CryptographicParameters cryptographicParameters)
    {
        if (value <= 0
            || value > cryptographicParameters.Q)
        {
            throw new VerificationFailedException("7.B/C", "Value was not in Zq.");
        }
    }
}

