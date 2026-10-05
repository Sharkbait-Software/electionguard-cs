using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.Verify.Ballot;

/// <summary>
/// Verification 7 (Adherence to vote limits), extended to the supplemental fields a contest declares
/// (§3.3.9):
/// <list type="bullet">
/// <item>The selection-limit proof (7.B-7.D, eq. 62 format) is over the combined ciphertext: the
/// selections, every supplemental field that counts toward the limit (the write-in count, when the
/// manifest says so), and the overvote indicator raised to L (p.39 and footnote 42). Without such
/// fields that is the plain aggregate (7.1, 7.2).</item>
/// <item>When the contest declares an undervote difference count u, its relation L - u = the sum of
/// the selections (p.38) is proved by a one-value range proof that the selections' and counted
/// fields' product times u's ciphertext encrypts L. Its challenge and response are checked as 7.B
/// and 7.C, and its challenge equation as 7.D, with messages that name the relation. The spec
/// defines no challenge format for this proof ("These proofs are not described in detail"); see
/// <see cref="ComputeUndervoteDifferenceChallenge"/>.</item>
/// <item>7.A covers every verifiable field's alpha and beta, supplemental fields included (§3.1.3
/// p.19: whenever the spec lists option fields "it is assumed that these include all verifiable
/// fields in that contest").</item>
/// </list>
/// The disjunctive indicator-consistency proofs of §3.3.9 (undervote indicator 1 iff the sum is
/// below L; null-vote indicator 1 iff the sum is 0) are not implemented (user decision Q2): an
/// indicator is checked only to be 0 or 1 (Verification 6). Neither is p.39's optional enforcement
/// of the null-vote indicator "just as the validity of the encrypted overvote indicator" (adding L
/// times it to the selection-limit proof), which Q2's list of relations leaves out; this is why
/// <see cref="Manifest.Validate"/> refuses a null-vote indicator that counts toward the limit.
/// </summary>
public class AdherenceToVoteLimitsVerification
{
    public void Verify(EncryptedBallot encryptedBallot, EncryptionRecord encryptionRecord)
    {
        // The proof challenges recomputed below hash the manifest's contest indices. They are
        // trusted here because EncryptionRecord validated the manifest (§3.1.3) when it was built;
        // re-validating the whole manifest per ballot would cost O(manifest) each time.

        // "All possible selections for the contest": exactly the ballot style's contests, the
        // manifest's options and the declared supplemental fields, each once, before anything else
        // (see BallotStructure).
        BallotStructure.Require(encryptedBallot, encryptionRecord.Manifest, 7);

        // 7.A, before any other 7.x check: every verifiable field's alpha_i and beta_i is in Z_p^r
        // (p.37: subscript i, no overbar; user decision Q8 "per-selection as written"). Two
        // non-members whose product is a member would pass a test of the aggregates alone. All of
        // the ballot's components go through one batch test; see SubgroupMembership for why it is
        // sound.
        //
        // The aggregates need no test of their own: Z_p^r is closed under multiplication, so once
        // every alpha_i and beta_i is a member, so are their products and powers. That is also why
        // this verification does not read membership off the range-proof squaring chains, as
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
            Verify(contest, manifestContest, challenge, encryptedBallot);
        }
    }

    /// <summary>Every verifiable field's alpha_i and beta_i, in ballot order.</summary>
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

    private static void Verify(EncryptedContest encryptedContest, Contest contest, RangeProofChallenge challenge, EncryptedBallot encryptedBallot)
    {
        // A null list or a null entry only comes from a malformed JSON document (protobuf cannot
        // encode one); it is reported like a list of the wrong length.
        if (encryptedContest.Proofs is null || encryptedContest.Proofs.Length != contest.SelectionLimit + 1 || HasNullEntry(encryptedContest.Proofs))
        {
            throw new VerificationFailedException("7", $"A challenge/response value was not provided for all possible values of the contest selection limit of {contest.SelectionLimit}.");
        }

        var undervoteDifference = contest.SupplementalFieldOfKind(SupplementalFieldKind.UndervoteDifferenceCount);
        ChallengeResponsePair[] relationProof = encryptedContest.UndervoteDifferenceProof ?? [];
        if (undervoteDifference is not null && relationProof.Length != 1)
        {
            throw new VerificationFailedException("7", $"Contest {contest.Id} declares an undervote difference count, so it must carry exactly one undervote difference proof (challenge, response); it carries {relationProof.Length}.");
        }

        if (undervoteDifference is null && relationProof.Length != 0)
        {
            throw new VerificationFailedException("7", $"Contest {contest.Id} declares no undervote difference count, but carries an undervote difference proof.");
        }

        if (HasNullEntry(relationProof))
        {
            throw new VerificationFailedException("7", $"Contest {contest.Id}'s undervote difference proof has a null entry in place of its (challenge, response).");
        }

        // 7.B/C for every proof before any exponentiation. Nothing below can throw, so this
        // raises exactly the exception, for exactly the inputs, that checking proof by proof did.
        ChallengeResponsePair[] proofs = encryptedContest.Proofs;
        for (int i = 0; i < proofs.Length; i++)
        {
            VerifyIsInZq(proofs[i].Challenge);
            VerifyIsInZq(proofs[i].Response);
        }

        for (int i = 0; i < relationProof.Length; i++)
        {
            VerifyIsInZq(relationProof[i].Challenge, "undervote difference proof: ");
            VerifyIsInZq(relationProof[i].Response, "undervote difference proof: ");
        }

        var (limit, relation) = Ciphertexts(encryptedContest, contest, challenge, undervoteDifference);

        var c = ComputeChallenge(contest, limit.Alpha, limit.Beta, proofs, challenge, encryptedBallot);
        if (SumOfChallenges(proofs) != c)
        {
            throw new VerificationFailedException("7.D", "Sum of challenge values did not equal c.");
        }

        if (undervoteDifference is not null)
        {
            var relationChallenge = ComputeUndervoteDifferenceChallenge(contest, undervoteDifference, relation.Alpha, relation.Beta, relationProof, challenge, encryptedBallot);
            if (relationProof[0].Challenge != relationChallenge)
            {
                throw new VerificationFailedException("7.D", $"Undervote difference proof of contest {contest.Id}: the challenge does not equal c, so L - u is not shown to equal the sum of the selections (§3.3.9).");
            }
        }
    }

    /// <summary>
    /// The contest's proof ciphertexts, computed alike by the encryptor and here, from "sum": the
    /// product of the selections and of every supplemental field of weight 1
    /// (<see cref="Contest.SelectionLimitWeight"/>), which encrypts the sum of the selections.
    /// <list type="bullet">
    /// <item>limit: sum times the overvote indicator raised to L, when one is declared (§3.3.9 p.39,
    /// footnote 42); the ciphertext of the selection-limit proof;</item>
    /// <item>relation: sum times the undervote difference count, when one is declared; the
    /// ciphertext of the undervote difference proof.</item>
    /// </list>
    /// L is a small public number, so the power is a short window over L's bits.
    /// </summary>
    private static ((IntegerModP Alpha, IntegerModP Beta) Limit, (IntegerModP Alpha, IntegerModP Beta) Relation) Ciphertexts(
        EncryptedContest encryptedContest,
        Contest contest,
        RangeProofChallenge challenge,
        SupplementalField? undervoteDifference)
    {
        EncryptedSupplementalField? overvote = null;
        EncryptedSupplementalField? difference = null;
        List<EncryptedValueWithProofs>? counted = null;
        foreach (var field in encryptedContest.SupplementalFields)
        {
            var declared = contest.SupplementalFields.Single(x => x.Id == field.FieldId);
            if (declared.Kind == SupplementalFieldKind.OvervoteIndicator)
            {
                overvote = field;
            }
            else if (declared.Kind == SupplementalFieldKind.UndervoteDifferenceCount)
            {
                difference = field;
            }
            else if (contest.SelectionLimitWeight(declared) == 1)
            {
                counted ??= new List<EncryptedValueWithProofs>(encryptedContest.Choices);
                counted.Add(field);
            }
        }

        // The product of the selections (7.1, 7.2), and of the counted fields.
        var sum = challenge.Aggregate(counted ?? (IReadOnlyList<EncryptedValueWithProofs>)encryptedContest.Choices);

        var limit = sum;
        if (overvote is not null)
        {
            var alpha = new ModPProduct(sum.Alpha);
            var beta = new ModPProduct(sum.Beta);
            alpha.MultiplyPower(overvote.Alpha, contest.SelectionLimit);
            beta.MultiplyPower(overvote.Beta, contest.SelectionLimit);
            limit = (alpha.Value, beta.Value);
        }

        var relation = sum;
        if (undervoteDifference is not null && difference is not null)
        {
            var alpha = new ModPProduct(sum.Alpha);
            var beta = new ModPProduct(sum.Beta);
            alpha.Multiply(difference.Alpha);
            beta.Multiply(difference.Beta);
            relation = (alpha.Value, beta.Value);
        }

        return (limit, relation);
    }

    /// <summary>
    /// c = H(H_I; 0x24, i, alpha, beta, a_0, b_0, ..., a_L, b_L) over the combined ciphertext
    /// (alpha, beta) (7.5, eq. 62), with a_j = g^v_j * alpha^c_j and b_j = K^(v_j - j * c_j) * beta^c_j.
    /// The prefix is everything before alpha; RangeProofChallenge computes the a_j and b_j and
    /// appends the rest.
    /// </summary>
    private static IntegerModQ ComputeChallenge(Contest contest, IntegerModP alpha, IntegerModP beta, ChallengeResponsePair[] proofs, RangeProofChallenge challenge, EncryptedBallot encryptedBallot)
    {
        Span<byte> prefix = stackalloc byte[5];
        prefix[0] = 0x24;
        RangeProofChallenge.WriteIndex(prefix.Slice(1, 4), contest.Index);

        return challenge.Compute(encryptedBallot.SelectionEncryptionIdentifierHash, prefix, alpha, beta, proofs);
    }

    /// <summary>
    /// The challenge of the undervote difference relation proof. NOT spec-defined (§3.3.9: these
    /// proofs "are not described in detail"), so not interoperable: this implementation uses eq.
    /// (59)'s range-proof format restricted, as Note 3.4 allows, to the singleton set {L}:
    /// c = H_q(H_I; 0x24, ind_c, ind_o(u), alpha, beta, a_L, b_L), where ind_o(u) is the undervote
    /// difference field's option index, (alpha, beta) the product of the sum ciphertext and u's
    /// ciphertext, a_L = g^v * alpha^c and b_L = K^(v - L * c) * beta^c. The proof is (c_L, v) with
    /// c_L = c. Its input is 2057 bytes after H_I; u's own range proof hashes the same prefix but has
    /// L + 1 &gt;= 2 commitment pairs, so the two inputs never coincide. L &gt;= 1 is a precondition
    /// that <see cref="Manifest.Validate"/> enforces when the record is built.
    /// </summary>
    private static IntegerModQ ComputeUndervoteDifferenceChallenge(Contest contest, SupplementalField undervoteDifference, IntegerModP alpha, IntegerModP beta, ChallengeResponsePair[] proofs, RangeProofChallenge challenge, EncryptedBallot encryptedBallot)
    {
        Span<byte> prefix = stackalloc byte[9];
        prefix[0] = 0x24;
        RangeProofChallenge.WriteIndex(prefix.Slice(1, 4), contest.Index);
        RangeProofChallenge.WriteIndex(prefix.Slice(5, 4), undervoteDifference.Index);

        return challenge.Compute(encryptedBallot.SelectionEncryptionIdentifierHash, prefix, alpha, beta, proofs, firstValue: contest.SelectionLimit);
    }

    private static bool HasNullEntry(ChallengeResponsePair[] proofs)
    {
        foreach (var proof in proofs)
        {
            if (proof is null)
            {
                return true;
            }
        }

        return false;
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

    private static void VerifyIsInZq(IntegerModQ value, string context = "")
    {
        if (!IsInZq(value))
        {
            throw new VerificationFailedException("7.B/C", $"{context}Value was not in Zq.");
        }
    }
}
