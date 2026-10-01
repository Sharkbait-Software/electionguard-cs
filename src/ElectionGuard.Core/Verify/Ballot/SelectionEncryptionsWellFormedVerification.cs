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

        // 6.B/C for every proof before any exponentiation. Nothing below can throw, so this
        // raises exactly the exception, for exactly the inputs, that checking proof by proof did.
        int proofCount = selection.Proofs.Length;
        IntegerModQ[] challenges = new IntegerModQ[proofCount];
        for (int i = 0; i < proofCount; i++)
        {
            VerifyIsInZq(selection.Proofs[i].Challenge);
            VerifyIsInZq(selection.Proofs[i].Response);
            challenges[i] = selection.Proofs[i].Challenge;
        }

        // alpha and beta are each raised to every challenge c_j. The challenges are public proof
        // data, so the verifier-only variable-time path, which shares one squaring chain across all
        // of a base's exponents, is safe here. g^v and K^w stay on PowModP, which uses their tables.
        IntegerModP[] alphaPowers = new IntegerModP[proofCount];
        IntegerModP[] betaPowers = new IntegerModP[proofCount];
        MontgomeryModP.PowModPVariableTime(selection.Alpha, challenges, alphaPowers);
        MontgomeryModP.PowModPVariableTime(selection.Beta, challenges, betaPowers);

        List<(IntegerModP a, IntegerModP b)> calculatedValues = new();
        for (int i = 0; i < proofCount; i++)
        {
            var crPair = selection.Proofs[i];

            var a = MontgomeryModP.PowModP(EGParameters.G, crPair.Response) * alphaPowers[i];
            var w = crPair.Response - i * crPair.Challenge;
            var b = MontgomeryModP.PowModP(encryptionRecord.ElectionPublicKeys.VoteEncryptionKey, w) * betaPowers[i];
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
