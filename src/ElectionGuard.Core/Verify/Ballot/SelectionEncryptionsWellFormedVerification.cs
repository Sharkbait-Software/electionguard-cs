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
        // 6.A for every selection on the ballot at once, before any proof is checked. Testing the
        // ballot's alphas and betas as one batch is what makes this affordable; see
        // SubgroupMembership for why the batch test is sound.
        var components = encryptedBallot.Contests
            .SelectMany(contest => contest.Choices)
            .SelectMany(choice => new[] { choice.Alpha, choice.Beta })
            .ToList();
        if (SubgroupMembership.IndexOfFirstNonMember(components) >= 0)
        {
            throw new VerificationFailedException("6.A", "Value was not in Zpr.");
        }

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
        if (selection.Proofs.Length != contest.OptionSelectionLimit + 1)
        {
            throw new VerificationFailedException("6", $"A challenge/response value was not provided for all possible values of the option selection limit of {contest.OptionSelectionLimit}.");
        }

        List<(IntegerModP a, IntegerModP b)> calculatedValues = new();
        for (int i = 0; i < selection.Proofs.Length; i++)
        {
            var crPair = selection.Proofs[i];

            VerifyIsInZq(crPair.Challenge);
            VerifyIsInZq(crPair.Response);

            var a = MontgomeryModP.PowModP(EGParameters.G, crPair.Response)
                * MontgomeryModP.PowModP(selection.Alpha, crPair.Challenge);
            var w = crPair.Response - i * crPair.Challenge;
            var b = MontgomeryModP.PowModP(encryptionRecord.ElectionPublicKeys.VoteEncryptionKey, w)
                * MontgomeryModP.PowModP(selection.Beta, crPair.Challenge);
            calculatedValues.Add((a, b));
        }

        List<byte[]> bytesToHash = [
                [0x24],
                contest.Index.ToByteArray(),
                choice.Index.ToByteArray(),
                selection.Alpha,
                selection.Beta];
        foreach (var val in calculatedValues)
        {
            bytesToHash.Add(val.a);
            bytesToHash.Add(val.b);
        }

        var c = EGHash.HashModQ(encryptedBallot.SelectionEncryptionIdentifierHash, bytesToHash.ToArray());

        var sumC = selection.Proofs.Select(x => x.Challenge).Sum();
        if (sumC != c)
        {
            throw new VerificationFailedException("6.D", "Sum of challenge values did not equal c.");
        }
    }

    private void VerifyIsInZq(IntegerModQ value)
    {
        if (value <= 0
            || value > EGParameters.Q)
        {
            throw new VerificationFailedException("6.B/C", "Value was not in Zq.");
        }
    }
}
