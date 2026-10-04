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

        // 7.A is read off the squaring chains the proof checks walk anyway, when the active q allows
        // it (see RangeProofChallenge). That reorders the work but must not reorder the failures:
        // 7.A for any contest is reported before any other failure. So the fused path runs only when
        // nothing but 7.A or 7.D can fail; otherwise the original order of checks runs instead.
        if (RangeProofChallenge.CanCheckMembership && PassesStructuralChecks(encryptedBallot, encryptionRecord))
        {
            VerifyFused(encryptedBallot, encryptionRecord, components, challenge);
        }
        else
        {
            VerifyInOrder(encryptedBallot, encryptionRecord, components, challenge);
        }
    }

    /// <summary>
    /// Whether every contest would pass every check other than 7.A and 7.D: it is in the manifest
    /// exactly once, it has one proof per possible selection count, and every challenge and response
    /// is in Z_q. Throws nothing, and allocates nothing, since it runs on every ballot.
    /// </summary>
    private static bool PassesStructuralChecks(EncryptedBallot encryptedBallot, EncryptionRecord encryptionRecord)
    {
        foreach (var contest in encryptedBallot.Contests)
        {
            Contest? manifestContest = null;
            int contestMatches = 0;
            foreach (var candidate in encryptionRecord.Manifest.Contests)
            {
                if (candidate.Id == contest.Id)
                {
                    manifestContest = candidate;
                    contestMatches++;
                }
            }

            if (contestMatches != 1 || contest.Proofs.Length != manifestContest!.SelectionLimit + 1)
            {
                return false;
            }

            foreach (var proof in contest.Proofs)
            {
                if (!IsInZq(proof.Challenge) || !IsInZq(proof.Response))
                {
                    return false;
                }
            }
        }

        return true;
    }

    /// <summary>
    /// The checks for a ballot that passes every structural check, with 7.A decided exactly from the
    /// range-proof chains rather than by a separate batch test. Only 7.A and 7.D can fail here, and
    /// 7.A for any contest must be reported before 7.D for any contest.
    /// </summary>
    private static void VerifyFused(EncryptedBallot encryptedBallot, EncryptionRecord encryptionRecord, List<IntegerModP> components, RangeProofChallenge challenge)
    {
        for (int i = 0; i < encryptedBallot.Contests.Count; i++)
        {
            var contest = encryptedBallot.Contests[i];
            var manifestContest = encryptionRecord.Manifest.Contests.Single(x => x.Id == contest.Id);
            var c = ComputeChallenge(contest, manifestContest, components[2 * i], components[2 * i + 1], challenge, encryptedBallot, checkMembership: true, out bool componentsAreMembers);
            if (!componentsAreMembers)
            {
                throw new VerificationFailedException("7.A", "Value was not in Zpr.");
            }

            if (SumOfChallenges(contest.Proofs) != c)
            {
                // A later contest's 7.A still takes precedence. Only a failing ballot gets here, so
                // the separate membership test of the in-order path is affordable.
                if (SubgroupMembership.IndexOfFirstNonMember(components) >= 0)
                {
                    throw new VerificationFailedException("7.A", "Value was not in Zpr.");
                }

                throw new VerificationFailedException("7.D", "Sum of challenge values did not equal c.");
            }
        }
    }

    private static void VerifyInOrder(EncryptedBallot encryptedBallot, EncryptionRecord encryptionRecord, List<IntegerModP> components, RangeProofChallenge challenge)
    {
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

        var c = ComputeChallenge(encryptedContest, contest, alpha, beta, challenge, encryptedBallot, checkMembership: false, out _);
        if (SumOfChallenges(proofs) != c)
        {
            throw new VerificationFailedException("7.D", "Sum of challenge values did not equal c.");
        }
    }

    /// <summary>
    /// c = H(H_I; 0x24, i, alpha, beta, a_0, b_0, ..., a_L, b_L) over the aggregate (alpha, beta),
    /// with a_j = g^v_j * alpha^c_j and b_j = K^(v_j - j * c_j) * beta^c_j. The prefix is
    /// everything before alpha; RangeProofChallenge computes the a_j and b_j and appends the rest.
    /// With <paramref name="checkMembership"/>, also reports whether alpha and beta are both in
    /// Z_p^r (7.A).
    /// </summary>
    private static IntegerModQ ComputeChallenge(EncryptedContest encryptedContest, Contest contest, IntegerModP alpha, IntegerModP beta, RangeProofChallenge challenge, EncryptedBallot encryptedBallot, bool checkMembership, out bool componentsAreMembers)
    {
        Span<byte> prefix = stackalloc byte[5];
        prefix[0] = 0x24;
        RangeProofChallenge.WriteIndex(prefix.Slice(1, 4), contest.Index);

        if (checkMembership)
        {
            return challenge.Compute(encryptedBallot.SelectionEncryptionIdentifierHash, prefix, alpha, beta, encryptedContest.Proofs, out componentsAreMembers);
        }

        componentsAreMembers = false;
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

    private static bool IsInZq(IntegerModQ value)
    {
        return !(value <= 0 || value > EGParameters.Q);
    }

    private static void VerifyIsInZq(IntegerModQ value)
    {
        if (!IsInZq(value))
        {
            throw new VerificationFailedException("7.B/C", "Value was not in Zq.");
        }
    }
}
