using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.Verify.Ballot;

/// <summary>
/// Verification 7 (Adherence to vote limits)
/// </summary>
public class AdherenceToVoteLimitsVerification
{
    public void Verify(EncryptedBallot encryptedBallot, EncryptionRecord encryptionRecord)
    {
        // The proof challenges recomputed below hash the manifest's contest indices. They are
        // trusted here because EncryptionRecord validated the manifest (§3.1.3) when it was built;
        // re-validating the whole manifest per ballot would cost O(manifest) each time.

        // "All possible selections for the contest": exactly the ballot style's contests and the
        // manifest's options, each once, before anything else (see BallotStructure).
        BallotStructure.Require(encryptedBallot, encryptionRecord.Manifest, 7);

        // 7.A, before any other 7.x check: every selection's alpha_i and beta_i is in Z_p^r (p.37:
        // subscript i, no overbar; user decision Q8 "per-selection as written"). Two non-members
        // whose product is a member would pass a test of the aggregates alone. All of the ballot's
        // components go through one batch test; see SubgroupMembership for why it is sound.
        //
        // The aggregates need no test of their own: Z_p^r is closed under multiplication, so once
        // every alpha_i and beta_i is a member, so are their products. That is also why this
        // verification does not read membership off the range-proof squaring chains, as
        // Verification 6 does: those chains are the aggregates', not the selections'.
        if (SubgroupMembership.IndexOfFirstNonMember(Components(encryptedBallot)) >= 0)
        {
            throw new VerificationFailedException("7.A", "Value was not in Zpr.");
        }

        // Looks up the g and K tables once for the whole ballot rather than once per exponentiation.
        var challenge = new RangeProofChallenge(encryptionRecord.ElectionPublicKeys.VoteEncryptionKey);
        foreach (var contest in encryptedBallot.Contests)
        {
            var manifestContest = encryptionRecord.Manifest.Contests.Single(x => x.Id == contest.Id);

            // The contest's aggregate ciphertext, the product of its selections' ciphertexts (7.1, 7.2).
            var (alpha, beta) = challenge.Aggregate(contest.Choices);
            Verify(contest, manifestContest, alpha, beta, challenge, encryptedBallot);
        }
    }

    /// <summary>Every selection's alpha_i and beta_i, in ballot order.</summary>
    private static List<IntegerModP> Components(EncryptedBallot encryptedBallot)
    {
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

        return components;
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

        var c = ComputeChallenge(encryptedContest, contest, alpha, beta, challenge, encryptedBallot);
        if (SumOfChallenges(proofs) != c)
        {
            throw new VerificationFailedException("7.D", "Sum of challenge values did not equal c.");
        }
    }

    /// <summary>
    /// c = H(H_I; 0x24, i, alpha, beta, a_0, b_0, ..., a_L, b_L) over the aggregate (alpha, beta),
    /// with a_j = g^v_j * alpha^c_j and b_j = K^(v_j - j * c_j) * beta^c_j. The prefix is
    /// everything before alpha; RangeProofChallenge computes the a_j and b_j and appends the rest.
    /// </summary>
    private static IntegerModQ ComputeChallenge(EncryptedContest encryptedContest, Contest contest, IntegerModP alpha, IntegerModP beta, RangeProofChallenge challenge, EncryptedBallot encryptedBallot)
    {
        Span<byte> prefix = stackalloc byte[5];
        prefix[0] = 0x24;
        RangeProofChallenge.WriteIndex(prefix.Slice(1, 4), contest.Index);

        return challenge.Compute(encryptedBallot.SelectionEncryptionIdentifierHash, prefix, alpha, beta, encryptedContest.Proofs);
    }

    private static IntegerModQ SumOfChallenges(ChallengeResponsePair[] proofs)
    {
        IntegerModQ sumC = 0;
        for (int i = 0; i < proofs.Length; i++)
        {
            sumC += proofs[i].Challenge;
        }

        return sumC;
    }

    /// <summary>
    /// Z_q = {x : 0 &lt;= x &lt; q} (7.B/7.C), so 0 is accepted: a prover may simulate a branch with
    /// c_j = 0. <see cref="IntegerModQ"/> holds only reduced values, so this holds by construction
    /// for anything built under the active q; what a record encodes is range-checked when it is
    /// decoded (<see cref="IntegerModQ.FromCanonicalBytes"/>).
    /// </summary>
    private static bool IsInZq(IntegerModQ value)
    {
        BigInteger x = value.ToBigInteger();
        return x >= 0 && x < EGParameters.Q;
    }

    private static void VerifyIsInZq(IntegerModQ value)
    {
        if (!IsInZq(value))
        {
            throw new VerificationFailedException("7.B/C", "Value was not in Zq.");
        }
    }
}
