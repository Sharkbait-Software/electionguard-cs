using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.RecordFormat;

namespace ElectionGuard.Core.Verify.PreEncryption;

/// <summary>
/// Verification 18 (Correctness of encryptions for uncast pre-encrypted ballots), §4.5 p.66 and
/// §6.2.8 p.98: the cut-and-choose audit of a pre-encrypted ballot the voter did not cast. With the
/// released encryption nonces ξ_{i,j,k} (eq. 121) the verifier recomputes, for each contest Λ_i and
/// each selection vector j on it,
/// (18.1) α_{i,j,k} = g^{ξ_{i,j,k}} mod p and (18.2) β_{i,j,k} = K^{δ_{j,k} + ξ_{i,j,k}} mod p, with
/// δ_{j,k} = 1 exactly where k is the position of the option the vector is labelled with (never for
/// a null vector); (18.3) ψ_{i,j}; (18.4) χ_i = H(H_I; 0x41, ind_c(Λ_i), sorted ψ); and confirms
/// (18.A) H_C = H(H_I; 0x42, χ_1, ..., χ_mB, B_C) with the ballot's B_C.
///
/// Because δ comes from the label, a vector printed beside one option that encrypts a one at
/// another's position (the attack the audit exists to catch) never matches its recomputation.
///
/// Readings and hardening (S9; see the tracker):
/// <list type="bullet">
/// <item>(18.2)-(18.4) are written with vectors of m_i entries and m_i hashes; eq. (115), the §5.5.5
/// table and 16.B hash all m + L hashes, null vectors included, which is what
/// <see cref="PreEncryptionPrimitives.GenerateContest"/> computes. This follows eq. (115) (as the KAT oracle does); the null vectors are recomputed like
/// the others, with δ = 0 throughout.</item>
/// <item>Each recomputed encryption is also compared with the published one under the same label
/// (reported as 18.A). The preamble asks that "all encryptions are correct encryptions of the
/// corresponding selections"; 18.A alone binds only the set of hashes, because χ sorts them. A
/// device that prints two honest vectors beside each other's options, and releases each label's
/// eq. (121) nonces honestly, changes no hash, no χ and no H_C, and the nonces recompute exactly the
/// honest set of vectors, so 16, 17, 19 and 18.A as lettered all accept the ballot, while the short
/// code printed beside one option is a vote for the other. The comparison catches it.</item>
/// <item>When the record also releases ξ_B (§4.4), every released ξ_{i,j,k} must be the eq. (121)
/// value derived from it (reported as 18.A).</item>
/// </list>
/// The ballot's shape, the released nonces' shape (one list of m nonces per vector, aligned with
/// the ballot) and a 32-byte ξ_B are checked first, as "18.structure". H_I is the ballot's
/// (Verification 5.B checks it against id_B).
/// </summary>
public class UncastBallotEncryptionVerification
{
    /// <summary>
    /// Verification 18 on an uncast ballot joined from its printed item and its release on an item decoded from the election record (design §4.8): a released nonce ≥ q, or a release that does not match its item (form, H_I, contests), fails 18.structure, then
    /// <see cref="RecordItemNotEvaluableException"/> if another verification's range finding left no
    /// domain object, then <see cref="Verify(PreEncryptedUncastBallot, EncryptionRecord)"/>. See <see cref="RecordItemGate"/>.
    /// </summary>
    internal void Verify(RecordDecoded<PreEncryptedUncastBallot> uncast, EncryptionRecord encryptionRecord)
    {
        Verify(RecordItemGate.Require(uncast, 18), encryptionRecord);
    }

    public void Verify(PreEncryptedUncastBallot uncast, EncryptionRecord encryptionRecord)
    {
        ArgumentNullException.ThrowIfNull(uncast);
        ArgumentNullException.ThrowIfNull(encryptionRecord);

        var ballot = uncast.Ballot ?? throw new VerificationFailedException("18.structure", "The uncast pre-encrypted ballot record has no ballot.");
        BallotStructure.Require(ballot, encryptionRecord.Manifest, 18);
        RequireReleasedNonces(uncast);

        var manifest = encryptionRecord.Manifest;
        var selectionHash = ballot.SelectionEncryptionIdentifierHash;
        var voteEncryptionKey = encryptionRecord.ElectionPublicKeys.VoteEncryptionKey;
        var contestHashes = new List<(int ContestIndex, ContestHash ContestHash)>(ballot.Contests.Count);

        for (int i = 0; i < ballot.Contests.Count; i++)
        {
            var contest = ballot.Contests[i];
            var released = uncast.Contests[i];
            var manifestContest = manifest.Contests.Single(x => x.Id == contest.ContestId);
            var options = manifestContest.Choices;
            int m = options.Count;
            var selectionHashes = new List<SelectionHash>(contest.Selections.Count);

            for (int j = 0; j < contest.Selections.Count; j++)
            {
                var selection = contest.Selections[j];
                var nonces = released.Selections[j].Nonces;

                // The position of the one: the labelled option's (option indices are 1..m in order,
                // Manifest.Validate); none for a null vector.
                int onePosition = selection.ChoiceId is null ? -1 : options.FindIndex(x => x.Id == selection.ChoiceId);

                var vector = new List<BallotEncryption.EncryptedValue>(m);
                for (int k = 0; k < m; k++)
                {
                    IntegerModQ nonce = nonces[k];
                    if (uncast.BallotNonce is { } ballotNonce)
                    {
                        IntegerModQ derived = new PreEncryptionNonce(selectionHash, ballotNonce, manifestContest.Index, selection.SelectionIndex, options[k].Index);
                        if (derived != nonce)
                        {
                            throw new VerificationFailedException("18.A", $"The released nonce ξ_{{i,j,k}} for ballot {ballot.Id}, contest {contest.ContestId}, vector {selection.SelectionIndex}, position {k + 1} is not H_q(H_I; 0x45, i, j, k, ξ_B) of the released ballot nonce (eq. 121).");
                        }
                    }

                    // (18.1) alpha = g^xi, (18.2) beta = K^(delta + xi). The nonce is published, but
                    // full width: the Montgomery path.
                    var alpha = MontgomeryModP.PowModP(EGParameters.G, nonce);
                    var beta = MontgomeryModP.PowModP(voteEncryptionKey, k == onePosition ? nonce + 1 : nonce);
                    var published = selection.Vector[k];
                    if (published.Alpha != alpha || published.Beta != beta)
                    {
                        string label = selection.ChoiceId ?? "a null vote";
                        throw new VerificationFailedException("18.A", $"Encryption {k + 1} of the vector labelled {label} (index {selection.SelectionIndex}) in contest {contest.ContestId} of uncast ballot {ballot.Id} is not Enc({(k == onePosition ? 1 : 0)}; ξ) for its released nonce (18.1, 18.2).");
                    }

                    vector.Add(new BallotEncryption.EncryptedValue { Alpha = alpha, Beta = beta });
                }

                // (18.3) psi_{i,j} = H(H_I; 0x40, alpha_{i,j,1}, beta_{i,j,1}, ...).
                selectionHashes.Add(new SelectionHash(selectionHash, vector));
            }

            // (18.4) chi_i = H(H_I; 0x41, ind_c(Lambda_i), psi sorted), all m + L hashes (eq. 115).
            contestHashes.Add((manifestContest.Index, ContestHash.ForPreEncryptedContest(selectionHash, manifestContest.Index, selectionHashes)));
        }

        // (18.A) H_C = H(H_I; 0x42, chi_1, ..., chi_mB, B_C), contests in contest index order.
        var confirmationCode = ConfirmationCode.ForPreEncryptedBallot(selectionHash, contestHashes.OrderBy(x => x.ContestIndex).Select(x => x.ContestHash), ballot.ChainingField);
        if (confirmationCode != ballot.ConfirmationCode)
        {
            throw new VerificationFailedException("18.A", $"The confirmation code of uncast pre-encrypted ballot {ballot.Id} is not the one its released nonces recompute (eq. 116).");
        }
    }

    /// <summary>"18.structure" unless the released nonces match the ballot's shape.</summary>
    private static void RequireReleasedNonces(PreEncryptedUncastBallot uncast)
    {
        var ballot = uncast.Ballot;
        if (uncast.BallotNonce is { } ballotNonce && ballotNonce.ToByteArray() is not { Length: BallotEncryption.BallotNonceEncryption.NonceBytes })
        {
            throw Structure(ballot.Id, $"its released ballot nonce is not {BallotEncryption.BallotNonceEncryption.NonceBytes} bytes");
        }

        if (uncast.Contests is null || uncast.Contests.Count != ballot.Contests.Count)
        {
            throw Structure(ballot.Id, $"it releases nonces for {uncast.Contests?.Count ?? 0} contests; the ballot has {ballot.Contests.Count}");
        }

        for (int i = 0; i < ballot.Contests.Count; i++)
        {
            var contest = ballot.Contests[i];
            var released = uncast.Contests[i];
            if (released is null || !string.Equals(released.ContestId, contest.ContestId, StringComparison.Ordinal)
                || released.Selections is null || released.Selections.Count != contest.Selections.Count)
            {
                throw Structure(ballot.Id, $"its released nonces for contest {i + 1} are not one list per selection vector of contest {contest.ContestId}");
            }

            for (int j = 0; j < contest.Selections.Count; j++)
            {
                var selection = contest.Selections[j];
                var nonces = released.Selections[j];
                if (nonces is null || nonces.SelectionIndex != selection.SelectionIndex || nonces.Nonces is null || nonces.Nonces.Count != selection.Vector.Count)
                {
                    throw Structure(ballot.Id, $"its released nonces for vector {selection.SelectionIndex} of contest {contest.ContestId} are not one nonce per encryption of that vector");
                }
            }
        }
    }

    private static VerificationFailedException Structure(string ballotId, string violation)
    {
        return new VerificationFailedException("18.structure", $"Uncast pre-encrypted ballot {ballotId}: {violation}.");
    }
}
