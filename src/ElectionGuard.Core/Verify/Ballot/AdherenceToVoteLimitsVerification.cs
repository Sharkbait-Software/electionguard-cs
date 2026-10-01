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
        // Looks up the g and K tables once for the whole ballot rather than once per exponentiation.
        var challenge = new RangeProofChallenge(encryptionRecord.ElectionPublicKeys.VoteEncryptionKey);

        // The aggregate ciphertext of each contest, the product of its selections' ciphertexts,
        // held as the flat list (alpha_0, beta_0, alpha_1, beta_1, ...) the batch test takes.
        var components = new List<IntegerModP>(2 * encryptedBallot.Contests.Count);
        foreach (var contest in encryptedBallot.Contests)
        {
            var (alpha, beta) = challenge.Aggregate(contest.Choices);
            components.Add(alpha);
            components.Add(beta);
        }

        // 7.A for every contest on the ballot at once, before any proof is checked. Testing the
        // aggregates as one batch is what makes this affordable; see SubgroupMembership for why the
        // batch test is sound.
        if (SubgroupMembership.IndexOfFirstNonMember(components) >= 0)
        {
            throw new VerificationFailedException("7.A", "Value was not in Zpr.");
        }

        for (int i = 0; i < encryptedBallot.Contests.Count; i++)
        {
            var contest = encryptedBallot.Contests[i];
            var manifestContest = encryptionRecord.Manifest.Contests.Single(x => x.Id == contest.Id);
            Verify(contest, manifestContest, components[2 * i], components[2 * i + 1], challenge, encryptedBallot);
        }
    }

    private static void Verify(EncryptedContest encryptedContest, Contest contest, IntegerModP alpha, IntegerModP beta, RangeProofChallenge challenge, EncryptedBallot encryptedBallot)
    {
        if (encryptedContest.Proofs.Length != contest.SelectionLimit + 1)
        {
            throw new VerificationFailedException("7", $"A challenge/response value was not provided for all possible values of the contest selection limit of {contest.SelectionLimit}.");
        }

        // 7.B/C for every proof before any exponentiation. Nothing below can throw, so this
        // raises exactly the exception, for exactly the inputs, that checking proof by proof did.
        ChallengeResponsePair[] proofs = encryptedContest.Proofs;
        for (int i = 0; i < proofs.Length; i++)
        {
            VerifyIsInZq(proofs[i].Challenge);
            VerifyIsInZq(proofs[i].Response);
        }

        // c = H(H_I; 0x24, i, alpha, beta, a_0, b_0, ..., a_L, b_L) over the aggregate (alpha, beta),
        // with a_j = g^v_j * alpha^c_j and b_j = K^(v_j - j * c_j) * beta^c_j. The prefix is
        // everything before alpha; RangeProofChallenge computes the a_j and b_j and appends the rest.
        Span<byte> prefix = stackalloc byte[5];
        prefix[0] = 0x24;
        RangeProofChallenge.WriteIndex(prefix.Slice(1, 4), contest.Index);

        var c = challenge.Compute(
            encryptedBallot.SelectionEncryptionIdentifierHash,
            prefix,
            alpha,
            beta,
            proofs);

        IntegerModQ sumC = 0;
        for (int i = 0; i < proofs.Length; i++)
        {
            sumC += proofs[i].Challenge;
        }

        if (sumC != c)
        {
            throw new VerificationFailedException("7.D", "Sum of challenge values did not equal c.");
        }
    }

    private static void VerifyIsInZq(IntegerModQ value)
    {
        if (value <= 0
            || value > EGParameters.Q)
        {
            throw new VerificationFailedException("7.B/C", "Value was not in Zq.");
        }
    }
}

