using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.Verify.Ballot;

/// <summary>
/// Verification 7 (Adherence to vote limits), extended to the supplemental fields a contest declares
/// (§3.3.9; user decisions Q13-Q16). With s the sum of the selections, w the write-in count and L
/// the contest selection limit, each relation below is over the product of the encryptions of the
/// selections and the write-in count (which always counts toward the limit, Q13) and of the terms
/// of the fields the contest declares, and only those (Q14: an undeclared field "doesn't matter at
/// all"). L times a field is its ciphertext raised to L (footnote 42, Q16).
/// <list type="bullet">
/// <item>(1) The selection-limit proof (7.B-7.D, eq. 62 format) shows that
/// s + w + L*overvote + undervote indicator lies in 0..L. Without declared fields that is the plain
/// aggregate (7.1, 7.2). An overvoted ballot has every selection and write-in at 0 and the overvote
/// indicator at 1; a ballot that keeps a selection beside the indicator, or sets the undervote
/// indicator with s + w = L, exceeds L.</item>
/// <item>(2) When the contest declares an undervote difference count u, a one-value range proof
/// shows that s + w + L*overvote + u = L exactly (p.38's relation with the overvote term). Its
/// challenge and response are checked as 7.B and 7.C, its challenge equation as 7.D, with messages
/// that name the relation; see <see cref="ComputeUndervoteDifferenceChallenge"/>.</item>
/// <item>(3) When the contest declares a null-vote indicator, a range proof shows that
/// s + w + L*overvote + L*null lies in 0..L, which enforces the indicator "just as the validity of
/// the encrypted overvote indicator" (p.39; Q15 "Null in its own check": in (1) it would count the
/// same missing vote as the undervote indicator twice). The overvote term, present when that
/// indicator is declared (user decision Q17), makes an overvote with a null-vote indicator of 1
/// exceed L, as p.39 ("the null vote indicator should be set to zero") and Q3 require. Checked as
/// 7.B, 7.C and 7.D like (2); see <see cref="ComputeNullVoteChallenge"/>.</item>
/// <item>7.A covers every verifiable field's alpha and beta, supplemental fields included (§3.1.3
/// p.19: whenever the spec lists option fields "it is assumed that these include all verifiable
/// fields in that contest").</item>
/// </list>
/// The spec defines no challenge format for (2) and (3) ("These proofs are not described in
/// detail"), so those are this implementation's own and not interoperable. The disjunctive
/// indicator-consistency proofs of §3.3.9 p.38-39 are not implemented (user decision Q2). With
/// every field declared, the relations leave exactly these inconsistent values unchecked (each
/// field is still range-checked by Verification 6):
/// <list type="bullet">
/// <item>an undervote indicator of 0 when s + w is below L (Q2);</item>
/// <item>a null-vote indicator of 0 when s + w = 0 (Q2).</item>
/// </list>
/// On an overvote, (1) forces the undervote indicator to 0 and (3) the null-vote indicator to 0,
/// both through their L*overvote terms.
/// Separately, and as in the spec, an overvote indicator of 1 is only ever checked against the
/// selections and write-ins being 0: an encrypted overvote (all zero, overvote 1, the other
/// indicators and u 0) is indistinguishable from a device reporting a null vote as an overvote.
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

        var nullVote = contest.SupplementalFieldOfKind(SupplementalFieldKind.NullVoteIndicator);
        ChallengeResponsePair[] nullVoteProof = encryptedContest.NullVoteProof ?? [];
        if (nullVote is not null && nullVoteProof.Length != contest.SelectionLimit + 1)
        {
            throw new VerificationFailedException("7", $"Contest {contest.Id} declares a null-vote indicator, so it must carry a null-vote proof with a (challenge, response) for each of the {contest.SelectionLimit + 1} values 0..L; it carries {nullVoteProof.Length}.");
        }

        if (nullVote is null && nullVoteProof.Length != 0)
        {
            throw new VerificationFailedException("7", $"Contest {contest.Id} declares no null-vote indicator, but carries a null-vote proof.");
        }

        if (HasNullEntry(nullVoteProof))
        {
            throw new VerificationFailedException("7", $"Contest {contest.Id}'s null-vote proof has a null entry in place of a (challenge, response).");
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

        for (int i = 0; i < nullVoteProof.Length; i++)
        {
            VerifyIsInZq(nullVoteProof[i].Challenge, "null-vote proof: ");
            VerifyIsInZq(nullVoteProof[i].Response, "null-vote proof: ");
        }

        var ciphertexts = Ciphertexts(encryptedContest, contest, challenge);

        // (1) s + w + L*overvote + undervote indicator in 0..L.
        var c = ComputeChallenge(contest, ciphertexts.Limit.Alpha, ciphertexts.Limit.Beta, proofs, challenge, encryptedBallot);
        if (SumOfChallenges(proofs) != c)
        {
            throw new VerificationFailedException("7.D", "Sum of challenge values did not equal c.");
        }

        // (2) s + w + L*overvote + u = L.
        if (undervoteDifference is not null)
        {
            var (alpha, beta) = ciphertexts.Difference!.Value;
            var relationChallenge = ComputeUndervoteDifferenceChallenge(contest, undervoteDifference, alpha, beta, relationProof, challenge, encryptedBallot);
            if (relationProof[0].Challenge != relationChallenge)
            {
                throw new VerificationFailedException("7.D", $"Undervote difference proof of contest {contest.Id}: the challenge does not equal c, so the sum of the selections, the write-ins, L times the overvote indicator and the undervote difference count u is not shown to equal L (§3.3.9).");
            }
        }

        // (3) s + w + L*overvote + L*null in 0..L.
        if (nullVote is not null)
        {
            var (alpha, beta) = ciphertexts.NullVote!.Value;
            var nullVoteChallenge = ComputeNullVoteChallenge(contest, nullVote, alpha, beta, nullVoteProof, challenge, encryptedBallot);
            if (SumOfChallenges(nullVoteProof) != nullVoteChallenge)
            {
                throw new VerificationFailedException("7.D", $"Null-vote proof of contest {contest.Id}: the sum of the challenges does not equal c, so the sum of the selections, the write-ins, L times the overvote indicator (where declared) and L times the null-vote indicator is not shown to lie in 0..L (§3.3.9 p.39).");
            }
        }
    }

    /// <summary>
    /// The contest's relation ciphertexts (see the class remarks), computed alike by the encryptor
    /// and here. The fields are found by kind through their labels; BallotStructure has already
    /// required exactly the declared fields, each once.
    /// </summary>
    private static ContestRelationCiphertexts Ciphertexts(EncryptedContest encryptedContest, Contest contest, RangeProofChallenge challenge)
    {
        EncryptedSupplementalField? overvote = null;
        EncryptedSupplementalField? undervote = null;
        EncryptedSupplementalField? difference = null;
        EncryptedSupplementalField? nullVote = null;
        List<EncryptedValueWithProofs>? sumTerms = null;
        foreach (var field in encryptedContest.SupplementalFields)
        {
            var declared = contest.SupplementalFields.Single(x => x.Id == field.FieldId);
            switch (declared.Kind)
            {
                case SupplementalFieldKind.OvervoteIndicator:
                    overvote = field;
                    break;
                case SupplementalFieldKind.UndervoteIndicator:
                    undervote = field;
                    break;
                case SupplementalFieldKind.UndervoteDifferenceCount:
                    difference = field;
                    break;
                case SupplementalFieldKind.NullVoteIndicator:
                    nullVote = field;
                    break;
                case SupplementalFieldKind.WriteInCount:
                    sumTerms ??= new List<EncryptedValueWithProofs>(encryptedContest.Choices);
                    sumTerms.Add(field);
                    break;
            }
        }

        return challenge.RelationCiphertexts(
            sumTerms ?? (IReadOnlyList<EncryptedValueWithProofs>)encryptedContest.Choices,
            overvote,
            undervote,
            difference,
            nullVote,
            contest.SelectionLimit);
    }

    /// <summary>
    /// c = H(H_I; 0x24, i, alpha, beta, a_0, b_0, ..., a_L, b_L) over the combined ciphertext
    /// (alpha, beta) (7.5, eq. 62), with a_j = g^v_j * alpha^c_j and b_j = K^(v_j - j * c_j) * beta^c_j.
    /// The prefix is everything before alpha; RangeProofChallenge computes the a_j and b_j and
    /// appends the rest. Its input is 5 + 1024 (L + 2) bytes after H_I.
    /// </summary>
    private static IntegerModQ ComputeChallenge(Contest contest, IntegerModP alpha, IntegerModP beta, ChallengeResponsePair[] proofs, RangeProofChallenge challenge, EncryptedBallot encryptedBallot)
    {
        Span<byte> prefix = stackalloc byte[5];
        prefix[0] = 0x24;
        RangeProofChallenge.WriteIndex(prefix.Slice(1, 4), contest.Index);

        return challenge.Compute(encryptedBallot.SelectionEncryptionIdentifierHash, prefix, alpha, beta, proofs);
    }

    /// <summary>
    /// The challenge of the undervote difference relation proof (2). NOT spec-defined (§3.3.9: these
    /// proofs "are not described in detail"), so not interoperable: this implementation uses eq.
    /// (59)'s range-proof format restricted, as Note 3.4 allows, to the singleton set {L}:
    /// c = H_q(H_I; 0x24, ind_c, ind_o(u), alpha, beta, a_L, b_L), where ind_o(u) is the undervote
    /// difference field's option index, (alpha, beta) the encryption of s + w + L*overvote + u (the
    /// overvote term when that indicator is declared), a_L = g^v * alpha^c and
    /// b_L = K^(v - L * c) * beta^c. The proof is (c_L, v) with c_L = c. Its input is
    /// 9 + 1024 * 2 = 2057 bytes after H_I. Every eq. (59) range proof has 9 + 1024 (B + 2) bytes
    /// with a bound B &gt;= 1 (u's own hashes the same prefix with B = L), the selection-limit proof
    /// 5 + 1024 (L + 2) and the null-vote proof 13 + 1024 (L + 2), so no two inputs coincide.
    /// L &gt;= 1 is a precondition that <see cref="Manifest.Validate"/> enforces when the record is
    /// built.
    /// </summary>
    private static IntegerModQ ComputeUndervoteDifferenceChallenge(Contest contest, SupplementalField undervoteDifference, IntegerModP alpha, IntegerModP beta, ChallengeResponsePair[] proofs, RangeProofChallenge challenge, EncryptedBallot encryptedBallot)
    {
        Span<byte> prefix = stackalloc byte[9];
        prefix[0] = 0x24;
        RangeProofChallenge.WriteIndex(prefix.Slice(1, 4), contest.Index);
        RangeProofChallenge.WriteIndex(prefix.Slice(5, 4), undervoteDifference.Index);

        return challenge.Compute(encryptedBallot.SelectionEncryptionIdentifierHash, prefix, alpha, beta, proofs, firstValue: contest.SelectionLimit);
    }

    /// <summary>
    /// The challenge of the null-vote relation proof (3). NOT spec-defined (§3.3.9 p.39 says the
    /// indicator "can be enforced just as the validity of the encrypted overvote indicator" but
    /// gives no format), so not interoperable. It is eq. (59)'s range proof over 0..L with the
    /// weight of the null term after the option index:
    /// c = H_q(H_I; 0x24, ind_c, ind_o(null), b(L, 4), alpha, beta, a_0, b_0, ..., a_L, b_L), where
    /// ind_o(null) is the null-vote indicator's option index, (alpha, beta) the encryption of
    /// s + w + L*overvote + L*null (the overvote term when that indicator is declared, user decision
    /// Q17), a_j = g^v_j * alpha^c_j and b_j = K^(v_j - j * c_j) * beta^c_j. b(L, 4) makes
    /// its input 13 + 1024 (L + 2) bytes after H_I, 13 mod 1024, while every other 0x24 input of the
    /// contest is 5 or 9 mod 1024 (see <see cref="ComputeUndervoteDifferenceChallenge"/>). Without
    /// it, at L = 1 the input would have the same prefix and length as the indicator's own 0..1
    /// range proof.
    /// </summary>
    private static IntegerModQ ComputeNullVoteChallenge(Contest contest, SupplementalField nullVote, IntegerModP alpha, IntegerModP beta, ChallengeResponsePair[] proofs, RangeProofChallenge challenge, EncryptedBallot encryptedBallot)
    {
        Span<byte> prefix = stackalloc byte[13];
        prefix[0] = 0x24;
        RangeProofChallenge.WriteIndex(prefix.Slice(1, 4), contest.Index);
        RangeProofChallenge.WriteIndex(prefix.Slice(5, 4), nullVote.Index);
        RangeProofChallenge.WriteIndex(prefix.Slice(9, 4), contest.SelectionLimit);

        return challenge.Compute(encryptedBallot.SelectionEncryptionIdentifierHash, prefix, alpha, beta, proofs);
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
