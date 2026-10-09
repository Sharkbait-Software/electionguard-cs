using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.RecordFormat;

namespace ElectionGuard.Core.Verify.Tally;

/// <summary>
/// Verification 13 (Correctness of decryptions for challenged ballots), §3.6.7 p.54 and §6.2.7 p.92.
///
/// For each contest Λ_i of a challenged ballot that was decrypted, with the released nonces ξ_{i,j}
/// and values σ_{i,j} of its m_i verifiable fields, the verifier recomputes (13.1) α_{i,j} = g^ξ_{i,j}
/// and (13.2) β_{i,j} = K^{σ_{i,j} + ξ_{i,j}}, and from them, with the ballot's encrypted contest data
/// (C_0, C_1, C_2), (13.3) the contest hash χ_i = H(H_I; 0x28, ind_c(Λ_i), α_{i,1}, β_{i,1}, ...,
/// C_0, C_1, C_2) (eq. 70; C_0, C_1, C_2 only where the contest carries contest data). With the
/// released contest data nonce ξ_i it computes (13.4) α = g^ξ_i, (13.5) β = K-hat^ξ_i,
/// (13.6) h = H(H_I; 0x26, ind_c(Λ), α, β) and (13.7) the keys k_l of eq. (66), and confirms
/// (13.A) C_1 = D_1 ⊕ k_1 ‖ ... ‖ D_{b_Λ} ⊕ k_{b_Λ}. Finally it confirms
/// (13.B) H_C = H(H_I; 0x29, χ_1, ..., χ_{m_B}, B_C), B_C being the ballot's chaining field.
///
/// 13.7 prints 0 &lt;= l &lt; b_Λ; the counter is 1-based, 1 &lt;= l &lt;= b_Λ, as in eqs. (66), (104) and
/// 12.4 (user decision Q6). A contest the record does not decrypt ("as might be the case in an RLA
/// setting") enters 13.B with the contest hash recomputed from the encrypted ballot, as Verification
/// 8 computes it. A wrong σ or a wrong ξ_{i,j} changes χ_i and therefore fails 13.B; a wrong D or a
/// wrong ξ_i fails 13.A.
///
/// The partial release is supported at contest granularity only. §3.6.7 p.52-53 also lets a
/// publication be "restricted to the desired subset of encryption nonces" within a contest, with the
/// verifier taking the given selection encryptions for the rest, but Verification 13 as lettered
/// recomputes every field of a decrypted contest ("For all 1 &lt;= j &lt;= m_i") and its own RLA
/// paragraph speaks only of contests that "have not been decrypted". So a decrypted contest must
/// release a nonce and value for every option and declared supplemental field, and its contest data
/// nonce and D where it carries contest data; a selection-level subset fails as "13.structure"
/// (open question Q-S7b in the fix tracker covers the RLA case as a whole).
///
/// 13.A also requires α = g^ξ_i (13.4) to equal the ballot's C_0. The spec's steps leave this
/// comparison out, but without it the contest data is not bound to the ballot: χ_i (13.3) hashes the
/// ballot's own (C_0, C_1, C_2), not α, so a publisher could release any ξ' together with
/// D' = C_1 ⊕ k(ξ'), and 13.A would hold by construction while 13.B is untouched. The selections need
/// no such check, because their recomputed (α_{i,j}, β_{i,j}) enter χ_i. This is library hardening
/// of a spec gap, like S6's C_0 membership check; the administrator already refuses to publish a ξ
/// that does not reproduce C_0 (<see cref="TallyAdmin.CombineChallengedBallot"/>), so an honest
/// record never meets it.
///
/// The spec numbers no check of the ballot nonce's Schnorr proof (eq. 38) here or anywhere: only the
/// guardians check it, before decrypting (§3.6.7 p.52; <see cref="TallyGuardian.DecryptBallotNonce"/>).
/// </summary>
public class ChallengedBallotDecryptionVerification
{
    /// <summary>
    /// Verification 13 on items decoded from the election record (design §4.8), the decryption and
    /// the encrypted ballot it opens: a released nonce ≥ q, a locator or H_I that is not the ballot's,
    /// or the ballot's C_ξB,0 ≥ p or c_B, v_B ≥ q fails 13.structure; then
    /// <see cref="RecordItemNotEvaluableException"/> if another verification's range finding is on
    /// either item (the ballot's 6.x, 7.x or 8.structure); then
    /// <see cref="Verify(EncryptionRecord, EncryptedBallot, DecryptedChallengedBallot)"/>. See <see cref="RecordItemGate"/>.
    /// </summary>
    internal void Verify(EncryptionRecord encryptionRecord, RecordDecoded<EncryptedBallot> ballot, RecordDecoded<DecryptedChallengedBallot> decrypted)
    {
        RecordItemGate.Require(13, decrypted, ballot);
        Verify(encryptionRecord, ballot.Value!, decrypted.Value!);
    }

    /// <summary>
    /// Verifies <paramref name="decrypted"/> against the challenged <paramref name="ballot"/>. K, K-hat,
    /// H_E (from which H_I is recomputed with the ballot's id_B), every index, b_Λ and the chaining mode
    /// come from <paramref name="encryptionRecord"/>; the chaining field B_C is formed from
    /// <paramref name="deviceInformationHash"/> and <paramref name="previousConfirmationCode"/> exactly
    /// as Verification 8 forms it. Throws <see cref="VerificationFailedException"/>:
    /// <list type="bullet">
    /// <item>"13.structure" if the decryption is for another ballot, the ballot is not recorded as
    /// challenged, is a pre-encrypted ballot's record (always cast, §4.3.1), is malformed
    /// (<see cref="BallotStructure"/>) or its H_I is not H(H_E; 0x20, id_B)
    /// (Verification 5.B), or a decrypted contest is not on the ballot, is listed twice, does not
    /// release exactly one nonce and value for each of the contest's options and declared
    /// supplemental fields, or releases contest data exactly where the ballot carries none (or none
    /// where it carries some). Contests and fields are matched by their indices
    /// (<see cref="DecryptedChallengedContest.Index"/>, <see cref="DecryptedChallengedField.Index"/>;
    /// design §4.6): the labels the decryption states are Verification 14's to check, so a
    /// mislabelled field is a 14.C/14.D failure, not a 13.x one against another field's
    /// ciphertext.</item>
    /// <item>"13.A", then "13.B", for the first lettered check that fails.</item>
    /// </list>
    /// </summary>
    public void Verify(
        EncryptionRecord encryptionRecord,
        EncryptedBallot ballot,
        DecryptedChallengedBallot decrypted,
        VotingDeviceInformationHash deviceInformationHash,
        ConfirmationCode? previousConfirmationCode)
    {
        ArgumentNullException.ThrowIfNull(encryptionRecord);
        Verify(encryptionRecord, ballot, decrypted, new ChainingField(encryptionRecord.Manifest.ChainingMode, deviceInformationHash, encryptionRecord.ExtendedBaseHash, previousConfirmationCode));
    }

    /// <summary>
    /// <see cref="Verify(EncryptionRecord, EncryptedBallot, DecryptedChallengedBallot, VotingDeviceInformationHash, ConfirmationCode?)"/>
    /// with 13.B over the chaining field the ballot carries ("B_C is the chaining field for ballot
    /// B"). That the field is the right one for the ballot's device and place in its device's chain
    /// is Verification 8.D/8.E (<see cref="Ballot.ConfirmationCodeVerification.VerifyDevice(DeviceChainRecord, IEnumerable{EncryptedBallot}, EncryptionRecord)"/>).
    /// </summary>
    public void Verify(
        EncryptionRecord encryptionRecord,
        EncryptedBallot ballot,
        DecryptedChallengedBallot decrypted)
    {
        ArgumentNullException.ThrowIfNull(ballot);
        Verify(encryptionRecord, ballot, decrypted, ballot.ChainingField);
    }

    private static void Verify(
        EncryptionRecord encryptionRecord,
        EncryptedBallot ballot,
        DecryptedChallengedBallot decrypted,
        ChainingField chainingField)
    {
        ArgumentNullException.ThrowIfNull(encryptionRecord);
        ArgumentNullException.ThrowIfNull(ballot);
        ArgumentNullException.ThrowIfNull(decrypted);

        string where = $"challenged ballot {ballot.Id}";
        if (decrypted.BallotId != ballot.Id)
        {
            throw Structure($"the decryption is for ballot {decrypted.BallotId}, not ballot {ballot.Id}.");
        }

        if (ballot.Status != BallotStatus.Challenged)
        {
            throw Structure($"{where} is recorded as {ballot.Status}, not as challenged; only challenged ballots are decrypted and published (§3.6.7).");
        }

        if (ballot.IsPreEncrypted)
        {
            throw Structure($"{where} is a pre-encrypted ballot's record, always a cast ballot's (§4.3.1); an uncast pre-encrypted ballot is published with its nonces and checked by Verification 18.");
        }

        var manifest = encryptionRecord.Manifest;
        if (BallotStructure.FindViolation(ballot, manifest) is string violation)
        {
            throw Structure(violation);
        }

        var selectionHash = new SelectionEncryptionIdentifierHash(encryptionRecord.ExtendedBaseHash, ballot.SelectionEncryptionIdentifier);
        if (!((byte[])selectionHash).AsSpan().SequenceEqual((byte[])ballot.SelectionEncryptionIdentifierHash))
        {
            throw Structure($"{where}'s H_I is not H(H_E; 0x20, id_B).");
        }

        // Keyed by index (design §4.6: "the index drives V13's ciphertext lookup"); the labels are
        // Verification 14's.
        var decryptedContests = new Dictionary<int, DecryptedChallengedContest>();
        foreach (var decryptedContest in decrypted.Contests ?? throw Structure($"the decryption of {where} has no contest list."))
        {
            if (decryptedContest is null)
            {
                throw Structure($"the decryption of {where} has a null contest entry.");
            }

            var onBallot = manifest.Contests.SingleOrDefault(x => x.Index == decryptedContest.Index);
            if (onBallot is null || !ballot.Contests.Any(x => x.Id == onBallot.Id))
            {
                throw Structure($"the decryption of {where} has contest index {decryptedContest.Index} ({decryptedContest.ContestId}), which is not a contest on the ballot.");
            }

            if (!decryptedContests.TryAdd(decryptedContest.Index, decryptedContest))
            {
                throw Structure($"the decryption of {where} lists contest index {decryptedContest.Index} more than once.");
            }
        }

        var voteEncryptionKey = encryptionRecord.ElectionPublicKeys.VoteEncryptionKey;
        var ballotDataKey = encryptionRecord.ElectionPublicKeys.OtherBallotDataEncryptionKey;
        var contestHashes = new List<(int Index, ContestHash Hash)>(ballot.Contests.Count);
        foreach (var contest in ballot.Contests)
        {
            var manifestContest = manifest.Contests.Single(x => x.Id == contest.Id);
            List<EncryptedValueWithProofs> fields;
            if (decryptedContests.TryGetValue(manifestContest.Index, out var decryptedContest))
            {
                // (13.1), (13.2): every value is public; ξ_{i,j} is a full-width element of Z_q.
                fields = new List<EncryptedValueWithProofs>(manifestContest.VerifiableFieldCount());
                fields.AddRange(Recompute(manifestContest.Choices, decryptedContest.Choices, "option"));
                fields.AddRange(Recompute(manifestContest.SupplementalFields, decryptedContest.SupplementalFields, "supplemental field"));

                // (13.4)-(13.7), 13.A.
                if ((contest.ContestData is null) != (decryptedContest.ContestData is null))
                {
                    throw Structure(contest.ContestData is null
                        ? $"the decryption of {where}, contest {contest.Id} releases contest data, but the contest carries none."
                        : $"the decryption of {where}, contest {contest.Id} releases no contest data nonce and D, but the contest carries a contest data field.");
                }

                if (contest.ContestData is { } encryptedData)
                {
                    var released = decryptedContest.ContestData!;
                    var alpha = MontgomeryModP.PowModP(EGParameters.G, released.EncryptionNonce);

                    // Library hardening the spec does not state: α of 13.4 must be the ballot's own
                    // C_0. Nothing else binds ξ_i to the ballot (χ_i hashes the ballot's C_0, C_1,
                    // C_2, not α), so without it any ξ' with D' = C_1 ⊕ k(ξ') would pass 13.A.
                    if (alpha != encryptedData.C0)
                    {
                        throw new VerificationFailedException("13.A", $"Challenged ballot decryption verification failed for {where}, contest {contest.Id}: α = g^ξ with the released contest data nonce ξ (13.4) is not the ballot's C_0, so ξ is not the nonce the contest data was encrypted with (eq. 67).");
                    }

                    var beta = MontgomeryModP.PowModP(ballotDataKey, released.EncryptionNonce);
                    var secretKey = ContestDataEncryption.SecretKey(selectionHash, manifestContest.Index, alpha, beta);
                    if (released.Data is null
                        || released.Data.Length != manifestContest.ContestDataLength()
                        || !ContestDataEncryption.Apply(secretKey, manifestContest.Index, manifestContest.ContestDataBlocks, released.Data).AsSpan().SequenceEqual(encryptedData.C1))
                    {
                        throw new VerificationFailedException("13.A", $"Challenged ballot decryption verification failed for {where}, contest {contest.Id}: C_1 is not D XOR k_1..k_b_Λ, the keys derived from h = H(H_I; 0x26, ind_c, g^ξ, K-hat^ξ) with the released contest data nonce ξ (13.4-13.7, eq. 66 with the counter from 1).");
                    }
                }
            }
            else
            {
                // Not decrypted: the contest hash recomputed from the encrypted ballot (13.B's RLA case).
                fields = new List<EncryptedValueWithProofs>(manifestContest.VerifiableFieldCount());
                fields.AddRange(manifestContest.Choices.Select(option => (EncryptedValueWithProofs)contest.Choices.Single(x => x.ChoiceId == option.Id)));
                fields.AddRange(manifestContest.SupplementalFields.Select(field => (EncryptedValueWithProofs)contest.SupplementalFields.Single(x => x.FieldId == field.Id)));
            }

            // (13.3), keyed by ind_c(Λ_i) (eq. 70's l), never by the contest's position on the ballot.
            contestHashes.Add((manifestContest.Index, new ContestHash(selectionHash, manifestContest.Index, fields, contest.ContestData)));

            List<EncryptedValueWithProofs> Recompute<T>(List<T> manifestFields, List<DecryptedChallengedField>? released, string kind)
                where T : Choice
            {
                if (released is null || released.Count != manifestFields.Count)
                {
                    throw Structure($"the decryption of {where}, contest {contest.Id} releases {released?.Count ?? 0} {kind} values; the contest has {manifestFields.Count}.");
                }

                var recomputed = new List<EncryptedValueWithProofs>(manifestFields.Count);
                foreach (var manifestField in manifestFields)
                {
                    // By index j, the j of eq. (33): a released label is compared in Verification 14.
                    var matches = released.Where(x => x is not null && x.Index == manifestField.Index).ToList();
                    if (matches.Count != 1)
                    {
                        throw Structure($"the decryption of {where}, contest {contest.Id} releases {matches.Count} values for {kind} {manifestField.Index} ({manifestField.Id}); it releases exactly one.");
                    }

                    var field = matches[0];
                    recomputed.Add(new EncryptedValueWithProofs
                    {
                        Alpha = MontgomeryModP.PowModP(EGParameters.G, field.EncryptionNonce),
                        Beta = MontgomeryModP.PowModP(voteEncryptionKey, field.EncryptionNonce + field.Value),
                        Proofs = [],
                    });
                }

                return recomputed;
            }
        }

        // 13.B over the contest hashes in contest-index order (eq. 71).
        var confirmationCode = new ConfirmationCode(selectionHash, contestHashes.OrderBy(x => x.Index).Select(x => x.Hash).ToList(), chainingField);
        if (confirmationCode != ballot.ConfirmationCode)
        {
            throw new VerificationFailedException("13.B", $"Challenged ballot decryption verification failed for {where}: H_C = H(H_I; 0x29, χ_1, ..., χ_m_B, B_C) over the contest hashes recomputed from the released nonces and values is not the ballot's confirmation code.");
        }

        VerificationFailedException Structure(string message) =>
            new("13.structure", $"Challenged ballot decryption verification failed: {message}");
    }
}
