using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using System.Numerics;

namespace ElectionGuard.Core.Verify.Tally;

/// <summary>
/// Verification 12 (Correctness of decryptions of contest data), §3.6.6 p.51 and §6.2.6 p.91.
///
/// For the contest data field (C_0, C_1, C_2) of contest Λ on a ballot, with its published
/// decryption (β, c, v) and data D, the verifier computes (12.1) a = g^v·K-hat^c and
/// (12.2) b = C_0^v·β^c, and confirms (12.A) v ∈ Z_q and
/// (12.B) c = H_q(H_I; 0x33, ind_c(Λ), C_0, C_1, C_2, a, b, β) (eq. 101); then computes
/// (12.3) h = H(H_I; 0x26, ind_c(Λ), C_0, β) and (12.4) the keys k_i for 1 &lt;= i &lt;= b_Λ (eq. 104),
/// and confirms (12.C) D = C_{1,1} ⊕ k_1 ‖ ... ‖ C_{1,b_Λ} ⊕ k_{b_Λ}.
///
/// Verification 12 does not include the guardians' check of the field's Schnorr proof C_2 (eq. 69,
/// §3.6.6 p.49-50); the spec puts that check on the guardians only, and so does this library
/// (<see cref="TallyGuardian.CommitContestData"/>, and the administrator before publishing). Nor
/// does it include the library's check, made in the same two places, that C_0 is in Z_p^r: the spec
/// states no such check, and a verifier that added it would reject records the spec accepts.
/// </summary>
public class ContestDataDecryptionVerification
{
    /// <summary>
    /// Verifies <paramref name="decrypted"/> against the contest data field of its contest on
    /// <paramref name="ballot"/>. K-hat, H_E (from which H_I is recomputed with the ballot's id_B),
    /// ind_c and b_Λ come from <paramref name="encryptionRecord"/>, never from the decryption.
    /// Throws <see cref="VerificationFailedException"/>:
    /// <list type="bullet">
    /// <item>"12.structure" if the decryption is not for this ballot, its contest is not in the
    /// manifest or declares no contest data, the ballot is malformed (<see cref="BallotStructure"/>),
    /// its published contest index is not the manifest's, or the ballot's H_I is not
    /// H(H_E; 0x20, id_B) (Verification 5.B): every value checked here is keyed with H_I.</item>
    /// <item>"12.A", "12.B" or "12.C", in that order, for the first lettered check that fails.</item>
    /// </list>
    /// </summary>
    public void Verify(EncryptionRecord encryptionRecord, EncryptedBallot ballot, DecryptedContestData decrypted)
    {
        ArgumentNullException.ThrowIfNull(encryptionRecord);
        ArgumentNullException.ThrowIfNull(ballot);
        ArgumentNullException.ThrowIfNull(decrypted);

        string where = $"ballot {ballot.Id}, contest {decrypted.ContestId}";
        if (decrypted.BallotId != ballot.Id)
        {
            throw new VerificationFailedException("12.structure", $"Contest data decryption verification failed: the decryption is for ballot {decrypted.BallotId}, not ballot {ballot.Id}.");
        }

        var contest = encryptionRecord.Manifest.Contests.FirstOrDefault(x => x.Id == decrypted.ContestId)
            ?? throw new VerificationFailedException("12.structure", $"Contest data decryption verification failed for {where}: the contest is not in the manifest, so ind_c and b_Λ are undefined.");
        if (contest.ContestDataBlocks == 0)
        {
            throw new VerificationFailedException("12.structure", $"Contest data decryption verification failed for {where}: the manifest declares no contest data for the contest.");
        }

        if (decrypted.ContestIndex != contest.Index)
        {
            throw new VerificationFailedException("12.structure", $"Contest data decryption verification failed for {where}: the decryption is published with contest index {decrypted.ContestIndex}, but the manifest gives the contest {contest.Index}.");
        }

        if (BallotStructure.FindViolation(ballot, encryptionRecord.Manifest) is string violation)
        {
            throw new VerificationFailedException("12.structure", $"Contest data decryption verification failed for {where}: {violation}");
        }

        var data = ballot.Contests.FirstOrDefault(x => x.Id == decrypted.ContestId)?.ContestData
            ?? throw new VerificationFailedException("12.structure", $"Contest data decryption verification failed for {where}: the ballot has no contest data field for the contest.");

        var selectionHash = new SelectionEncryptionIdentifierHash(encryptionRecord.ExtendedBaseHash, ballot.SelectionEncryptionIdentifier);
        if (!((byte[])selectionHash).AsSpan().SequenceEqual((byte[])ballot.SelectionEncryptionIdentifierHash))
        {
            throw new VerificationFailedException("12.structure", $"Contest data decryption verification failed for {where}: the ballot's H_I is not H(H_E; 0x20, id_B).");
        }

        // 12.A. An IntegerModQ holds only values in [0, q), and the strict decoders reject anything
        // else (G23), so this is an invariant; it is checked as Verification 12 states it.
        BigInteger v = decrypted.Response.ToBigInteger();
        if (v < 0 || v >= EGParameters.Q)
        {
            throw new VerificationFailedException("12.A", $"Contest data decryption verification failed for {where}: the response v is not in Z_q.");
        }

        // (12.1), (12.2). Every value is public; c and v are full-width elements of Z_q.
        var ballotDataKey = encryptionRecord.ElectionPublicKeys.OtherBallotDataEncryptionKey;
        var a = MontgomeryModP.PowModP(EGParameters.G, decrypted.Response) * MontgomeryModP.PowModP(ballotDataKey, decrypted.Challenge);
        var b = MontgomeryModP.PowModP(data.C0, decrypted.Response) * MontgomeryModP.PowModP(decrypted.Beta, decrypted.Challenge);

        // 12.B.
        if (ContestDataDecryptionHashes.Challenge(selectionHash, contest.Index, data, a, b, decrypted.Beta) != decrypted.Challenge)
        {
            throw new VerificationFailedException("12.B", $"Contest data decryption verification failed for {where}: the challenge c is not H_q(H_I; 0x33, ind_c, C_0, C_1, C_2, a, b, β) (eq. 101).");
        }

        // (12.3), (12.4), 12.C.
        var expected = ContestDataEncryption.Decrypt(selectionHash, contest.Index, contest.ContestDataBlocks, data, decrypted.Beta);
        if (decrypted.Data is null || !expected.AsSpan().SequenceEqual(decrypted.Data))
        {
            throw new VerificationFailedException("12.C", $"Contest data decryption verification failed for {where}: D is not C_1 XOR k_1..k_b_Λ, the keys derived from h = H(H_I; 0x26, ind_c, C_0, β) (eqs. 104-106).");
        }
    }
}
