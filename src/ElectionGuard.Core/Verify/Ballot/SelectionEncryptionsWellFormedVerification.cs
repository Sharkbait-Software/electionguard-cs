using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.Verify.Ballot;

/// <summary>
/// Verification 6 (Well-formedness of selection encryptions), over every verifiable field of every
/// contest: each selectable option, with its range 0..R, and each supplemental field the manifest
/// declares (§3.1.3 p.19: they are "treated like and listed with the option selection fields"), with
/// its own range (<see cref="Contest.RangeBound(Choice)"/>: 1 for an indicator, L for the undervote
/// difference count, the number of write-in fields for the write-in count).
/// </summary>
public class SelectionEncryptionsWellFormedVerification
{
    public void Verify(EncryptedBallot encryptedBallot, EncryptionRecord encryptionRecord)
    {
        // The proof challenges recomputed below hash the manifest's contest and option indices. They
        // are trusted here because EncryptionRecord validated the manifest (§3.1.3) when it was
        // built; re-validating the whole manifest per ballot would cost O(manifest) each time.

        // "For each selectable option within each contest": exactly the ballot style's contests, the
        // manifest's options and the declared supplemental fields, each once, before anything else
        // (see BallotStructure).
        BallotStructure.Require(encryptedBallot, encryptionRecord.Manifest, 6);

        // 6.A is read off the squaring chains the proof checks walk anyway, when the active q allows
        // it (see RangeProofChallenge). That reorders the work but must not reorder the failures:
        // 6.A for any field is reported before any other failure. So the fused path runs only when
        // nothing but 6.A or 6.D can fail; otherwise the original order of checks runs instead.
        if (RangeProofChallenge.CanCheckMembership && PassesStructuralChecks(encryptedBallot, encryptionRecord))
        {
            VerifyFused(encryptedBallot, encryptionRecord);
        }
        else
        {
            VerifyInOrder(encryptedBallot, encryptionRecord);
        }
    }

    /// <summary>
    /// Whether every verifiable field would pass every check other than 6.A and 6.D: its contest and
    /// its option or supplemental field are each in the manifest exactly once, it has one proof per
    /// possible value, and every challenge and response is in Z_q. Throws nothing, and allocates
    /// nothing, since it runs on every ballot.
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

            if (contestMatches != 1)
            {
                return false;
            }

            foreach (var choice in contest.Choices)
            {
                int choiceMatches = 0;
                foreach (var candidate in manifestContest!.Choices)
                {
                    if (candidate.Id == choice.ChoiceId)
                    {
                        choiceMatches++;
                    }
                }

                if (choiceMatches != 1 || !ProofsAreWellFormed(choice.Proofs, manifestContest.OptionSelectionLimit))
                {
                    return false;
                }
            }

            foreach (var field in contest.SupplementalFields)
            {
                SupplementalField? declared = null;
                int fieldMatches = 0;
                foreach (var candidate in manifestContest!.SupplementalFields)
                {
                    if (candidate.Id == field.FieldId)
                    {
                        declared = candidate;
                        fieldMatches++;
                    }
                }

                if (fieldMatches != 1 || !ProofsAreWellFormed(field.Proofs, manifestContest.RangeBound(declared!.Kind)))
                {
                    return false;
                }
            }
        }

        return true;
    }

    /// <summary>One proof per value 0..<paramref name="bound"/>, each challenge and response in Z_q.</summary>
    private static bool ProofsAreWellFormed(ChallengeResponsePair[] proofs, int bound)
    {
        if (!HasOneProofPerValue(proofs, bound))
        {
            return false;
        }

        foreach (var proof in proofs)
        {
            if (!IsInZq(proof.Challenge) || !IsInZq(proof.Response))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// A non-null list of <paramref name="bound"/> + 1 non-null proofs. A null list or entry only
    /// comes from a malformed JSON document (protobuf cannot encode one); it is reported like a list
    /// of the wrong length.
    /// </summary>
    private static bool HasOneProofPerValue(ChallengeResponsePair[]? proofs, int bound)
    {
        if (proofs is null || proofs.Length != bound + 1)
        {
            return false;
        }

        foreach (var proof in proofs)
        {
            if (proof is null)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// The checks for a ballot that passes every structural check, with 6.A decided exactly from the
    /// range-proof chains rather than by a separate batch test. Only 6.A and 6.D can fail here, and
    /// 6.A for any verifiable field must be reported before 6.D for any.
    /// </summary>
    private static void VerifyFused(EncryptedBallot encryptedBallot, EncryptionRecord encryptionRecord)
    {
        var challenge = new RangeProofChallenge(encryptionRecord.ElectionPublicKeys.VoteEncryptionKey);
        bool sumFailed = false;
        foreach (var contest in encryptedBallot.Contests)
        {
            var manifestContest = encryptionRecord.Manifest.Contests.Single(x => x.Id == contest.Id);
            foreach (var choice in contest.Choices)
            {
                var manifestChoice = manifestContest.Choices.Single(x => x.Id == choice.ChoiceId);
                if (!FusedCheckPasses(choice, manifestContest, manifestChoice, challenge, encryptedBallot))
                {
                    sumFailed = true;
                    break;
                }
            }

            if (sumFailed)
            {
                break;
            }

            foreach (var field in contest.SupplementalFields)
            {
                var declared = manifestContest.SupplementalFields.Single(x => x.Id == field.FieldId);
                if (!FusedCheckPasses(field, manifestContest, declared, challenge, encryptedBallot))
                {
                    sumFailed = true;
                    break;
                }
            }

            if (sumFailed)
            {
                break;
            }
        }

        if (sumFailed)
        {
            // A later field's 6.A still takes precedence. Only a failing ballot gets here, so the
            // separate membership test of the in-order path is affordable.
            if (SubgroupMembership.IndexOfFirstNonMember(Components(encryptedBallot)) >= 0)
            {
                throw new VerificationFailedException("6.A", "Value was not in Zpr.");
            }

            throw new VerificationFailedException("6.D", "Sum of challenge values did not equal c.");
        }
    }

    /// <summary>
    /// 6.A (throwing) and 6.D (returning false on failure) for one verifiable field, both read off
    /// one recomputation of its challenge.
    /// </summary>
    private static bool FusedCheckPasses(EncryptedValueWithProofs value, Contest contest, Choice field, RangeProofChallenge challenge, EncryptedBallot encryptedBallot)
    {
        var c = ComputeChallenge(value, contest, field, challenge, encryptedBallot, checkMembership: true, out bool componentsAreMembers);
        if (!componentsAreMembers)
        {
            throw new VerificationFailedException("6.A", "Value was not in Zpr.");
        }

        return SumOfChallenges(value.Proofs) == c;
    }

    /// <summary>
    /// Every verifiable field's alpha and beta, in ballot order: each contest's selections, then its
    /// supplemental fields.
    /// </summary>
    private static List<IntegerModP> Components(EncryptedBallot encryptedBallot)
    {
        int fieldCount = 0;
        foreach (var contest in encryptedBallot.Contests)
        {
            fieldCount += contest.Choices.Count + contest.SupplementalFields.Count;
        }

        var components = new List<IntegerModP>(2 * fieldCount);
        foreach (var contest in encryptedBallot.Contests)
        {
            foreach (var choice in contest.Choices)
            {
                components.Add(choice.Alpha);
                components.Add(choice.Beta);
            }

            foreach (var field in contest.SupplementalFields)
            {
                components.Add(field.Alpha);
                components.Add(field.Beta);
            }
        }

        return components;
    }

    private static void VerifyInOrder(EncryptedBallot encryptedBallot, EncryptionRecord encryptionRecord)
    {
        // 6.A for every verifiable field on the ballot at once, before any proof is checked. Testing
        // the ballot's alphas and betas as one batch is what makes this affordable; see
        // SubgroupMembership for why the batch test is sound.
        if (SubgroupMembership.IndexOfFirstNonMember(Components(encryptedBallot)) >= 0)
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

            foreach (var field in contest.SupplementalFields)
            {
                var declared = manifestContest.SupplementalFields.Single(x => x.Id == field.FieldId);
                Verify(field, manifestContest, declared, challenge, encryptedBallot);
            }
        }
    }

    /// <summary>
    /// 6.B-6.D for one verifiable field: a selectable option, whose range is 0..R, or a supplemental
    /// field, whose range is 0..its bound (<see cref="Contest.RangeBound(Choice)"/>).
    /// </summary>
    private static void Verify(EncryptedValueWithProofs selection, Contest contest, Choice choice, RangeProofChallenge challenge, EncryptedBallot encryptedBallot)
    {
        int bound = contest.RangeBound(choice);
        if (!HasOneProofPerValue(selection.Proofs, bound))
        {
            throw new VerificationFailedException("6", $"A challenge/response value was not provided for all possible values 0..{bound} of {choice.Id} in contest {contest.Id}.");
        }

        // 6.B/C for every proof before any exponentiation. Nothing below can throw, so this
        // raises exactly the exception, for exactly the inputs, that checking proof by proof did.
        ChallengeResponsePair[] proofs = selection.Proofs;
        for (int i = 0; i < proofs.Length; i++)
        {
            VerifyIsInZq(proofs[i].Challenge);
            VerifyIsInZq(proofs[i].Response);
        }

        var c = ComputeChallenge(selection, contest, choice, challenge, encryptedBallot, checkMembership: false, out _);
        if (SumOfChallenges(proofs) != c)
        {
            throw new VerificationFailedException("6.D", "Sum of challenge values did not equal c.");
        }
    }

    /// <summary>
    /// c = H(H_I; 0x24, i, j, alpha, beta, a_0, b_0, ..., a_R, b_R) (6.3), with j the option index of
    /// the option or supplemental field, a_j = g^v_j * alpha^c_j and b_j = K^(v_j - j * c_j) * beta^c_j.
    /// The prefix is everything before alpha; RangeProofChallenge computes the a_j and b_j and
    /// appends the rest. With <paramref name="checkMembership"/>, also reports whether alpha and
    /// beta are both in Z_p^r (6.A).
    /// </summary>
    private static IntegerModQ ComputeChallenge(EncryptedValueWithProofs selection, Contest contest, Choice choice, RangeProofChallenge challenge, EncryptedBallot encryptedBallot, bool checkMembership, out bool componentsAreMembers)
    {
        Span<byte> prefix = stackalloc byte[9];
        prefix[0] = 0x24;
        RangeProofChallenge.WriteIndex(prefix.Slice(1, 4), contest.Index);
        RangeProofChallenge.WriteIndex(prefix.Slice(5, 4), choice.Index);

        if (checkMembership)
        {
            return challenge.Compute(encryptedBallot.SelectionEncryptionIdentifierHash, prefix, selection.Alpha, selection.Beta, selection.Proofs, out componentsAreMembers);
        }

        componentsAreMembers = false;
        return challenge.Compute(encryptedBallot.SelectionEncryptionIdentifierHash, prefix, selection.Alpha, selection.Beta, selection.Proofs);
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
    /// Z_q = {x : 0 &lt;= x &lt; q} (6.B/6.C), so 0 is accepted: a prover may simulate a branch with
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
            throw new VerificationFailedException("6.B/C", "Value was not in Zq.");
        }
    }
}
