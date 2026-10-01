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
        int selectionCount = 0;
        foreach (var contest in encryptedBallot.Contests)
        {
            selectionCount += contest.Choices.Count;
        }

        var components = new List<IntegerModP>(2 * selectionCount);
        foreach (var contest in encryptedBallot.Contests)
        {
            foreach (var choice in contest.Choices)
            {
                components.Add(choice.Alpha);
                components.Add(choice.Beta);
            }
        }

        if (SubgroupMembership.IndexOfFirstNonMember(components) >= 0)
        {
            throw new VerificationFailedException("6.A", "Value was not in Zpr.");
        }

        // Looks up the g and K tables once for the whole ballot rather than once per exponentiation.
        var challenge = new RangeProofChallenge(encryptionRecord.ElectionPublicKeys.VoteEncryptionKey);
        foreach (var contest in encryptedBallot.Contests)
        {
            var manifestContest = encryptionRecord.Manifest.Contests.Single(x => x.Id == contest.Id);
            foreach (var choice in contest.Choices)
            {
                var manifestChoice = manifestContest.Choices.Single(x => x.Id == choice.ChoiceId);
                Verify(choice, manifestContest, manifestChoice, challenge, encryptedBallot);
            }
        }
    }

    private static void Verify(EncryptedValueWithProofs selection, Contest contest, Choice choice, RangeProofChallenge challenge, EncryptedBallot encryptedBallot)
    {
        if (selection.Proofs.Length != contest.OptionSelectionLimit + 1)
        {
            throw new VerificationFailedException("6", $"A challenge/response value was not provided for all possible values of the option selection limit of {contest.OptionSelectionLimit}.");
        }

        // 6.B/C for every proof before any exponentiation. Nothing below can throw, so this
        // raises exactly the exception, for exactly the inputs, that checking proof by proof did.
        ChallengeResponsePair[] proofs = selection.Proofs;
        for (int i = 0; i < proofs.Length; i++)
        {
            VerifyIsInZq(proofs[i].Challenge);
            VerifyIsInZq(proofs[i].Response);
        }

        // c = H(H_I; 0x24, i, j, alpha, beta, a_0, b_0, ..., a_L, b_L), with
        // a_j = g^v_j * alpha^c_j and b_j = K^(v_j - j * c_j) * beta^c_j. The prefix is everything
        // before alpha; RangeProofChallenge computes the a_j and b_j and appends the rest.
        Span<byte> prefix = stackalloc byte[9];
        prefix[0] = 0x24;
        RangeProofChallenge.WriteIndex(prefix.Slice(1, 4), contest.Index);
        RangeProofChallenge.WriteIndex(prefix.Slice(5, 4), choice.Index);

        var c = challenge.Compute(
            encryptedBallot.SelectionEncryptionIdentifierHash,
            prefix,
            selection.Alpha,
            selection.Beta,
            proofs);

        IntegerModQ sumC = 0;
        for (int i = 0; i < proofs.Length; i++)
        {
            sumC += proofs[i].Challenge;
        }

        if (sumC != c)
        {
            throw new VerificationFailedException("6.D", "Sum of challenge values did not equal c.");
        }
    }

    private static void VerifyIsInZq(IntegerModQ value)
    {
        if (value <= 0
            || value > EGParameters.Q)
        {
            throw new VerificationFailedException("6.B/C", "Value was not in Zq.");
        }
    }
}
