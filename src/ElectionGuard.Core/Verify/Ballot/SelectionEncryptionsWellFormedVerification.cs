using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.Verify.Ballot;

/// <summary>
/// Verification 6 (Well-formedness of selection encryptions)
/// </summary>
public class SelectionEncryptionsWellFormedVerification
{
    public void Verify(EncryptedBallot encryptedBallot, EncryptionRecord encryptionRecord)
    {
        foreach (var contest in encryptedBallot.Contests)
        {
            var manifestContest = encryptionRecord.Manifest.Contests.Single(x => x.Id == contest.Id);
            foreach (var choice in contest.Choices)
            {
                var manifestChoice = manifestContest.Choices.Single(x => x.Id == choice.ChoiceId);
                Verify(choice, manifestContest, manifestChoice, encryptionRecord, encryptedBallot);
            }
        }
    }

    private void Verify(EncryptedValueWithProofs selection, Contest contest, Choice choice, EncryptionRecord encryptionRecord, EncryptedBallot encryptedBallot)
    {
        if (selection.Proofs.Length != contest.OptionSelectionLimit)
        {
            throw new VerificationFailedException("6", $"A challenge/response value was not provided for all possible values of the option selection limit of {contest.OptionSelectionLimit}.");
        }

        List<(IntegerModP a, IntegerModP b)> calculatedValues = new();
        for (int i = 0; i < selection.Proofs.Length; i++)
        {
            var crPair = selection.Proofs[i];

            VerifyIsInZq(crPair.Challenge, encryptionRecord.CryptographicParameters);
            VerifyIsInZq(crPair.Response, encryptionRecord.CryptographicParameters);

            var a = IntegerModP.PowModP(encryptionRecord.CryptographicParameters.G, crPair.Response)
                * IntegerModP.PowModP(selection.Value.Alpha, crPair.Challenge);
            var w = crPair.Response - i * crPair.Challenge;
            var b = IntegerModP.PowModP(encryptionRecord.ElectionPublicKeys.VoteEncryptionKey, w)
                * IntegerModP.PowModP(selection.Value.Beta, crPair.Challenge);
            calculatedValues.Add((a, b));
        }

        List<byte[]> bytesToHash = [
                [0x24],
                contest.Index.ToByteArray(),
                choice.Index.ToByteArray(),
                selection.Value.Alpha,
                selection.Value.Beta];
        foreach (var val in calculatedValues)
        {
            bytesToHash.Add(val.a);
            bytesToHash.Add(val.b);
        }

        var c = EGHash.HashModQ(encryptedBallot.SelectionEncryptionIdentifierHash, bytesToHash.ToArray());

        VerifyIsInZpr(selection.Value.Alpha, encryptionRecord.CryptographicParameters);
        VerifyIsInZpr(selection.Value.Beta, encryptionRecord.CryptographicParameters);

        var sumC = selection.Proofs.Select(x => x.Challenge).Sum();
        if (sumC != c)
        {
            throw new VerificationFailedException("6.D", "Sum of challenge values did not equal c.");
        }
    }

    private void VerifyIsInZpr(IntegerModP value, CryptographicParameters cryptographicParameters)
    {
        // 6.A
        if (value <= 0
            || value > cryptographicParameters.P
            || IntegerModP.PowModP(value, cryptographicParameters.Q) != 1)
        {
            throw new VerificationFailedException("6.A", "Value was not in Zpr.");
        }
    }

    private void VerifyIsInZq(IntegerModQ value, CryptographicParameters cryptographicParameters)
    {
        if (value <= 0
            || value > cryptographicParameters.Q)
        {
            throw new VerificationFailedException("6.B/C", "Value was not in Zq.");
        }
    }
}
