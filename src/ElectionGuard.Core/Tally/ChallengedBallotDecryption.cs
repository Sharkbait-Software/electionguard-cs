using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Verify;

namespace ElectionGuard.Core.Tally;

/// <summary>
/// A guardian's partial decryption of a challenged ballot's encrypted nonce (§3.6.7 p.52, eq. 107):
/// m_i = C_ξB,0^{ẑ_i} mod p, with its ballot data encryption key share ẑ_i
/// (<see cref="TallyGuardian.DecryptBallotNonce"/>). It is the only message: §3.6.7 defines no proof
/// of correct decryption for the ballot nonce, because ξ_B is never published. What is published,
/// the encryption nonces derived from it, is checked by Verification 13 against the ballot's own
/// ciphertexts.
/// </summary>
public class BallotNoncePartialDecryption
{
    public required GuardianIndex GuardianIndex { get; init; }
    public required string BallotId { get; init; }

    /// <summary>m_i = C_ξB,0^{ẑ_i} mod p (eq. 107).</summary>
    public required IntegerModP Mi { get; init; }
}

/// <summary>
/// The published decryption of a challenged ballot (§3.6.7 "Verifying decryption with nonces";
/// §3.7 "The decryption of each challenged ballot: the selections made on the ballot, the plaintext
/// representation of the selections, ... decryption nonces"). For every contest of the ballot it
/// releases, for each verifiable field, the plaintext value σ_{i,j} and the encryption nonce
/// ξ_{i,j} (eq. 33), and, where the contest carries contest data, the contest data nonce ξ_i
/// (eq. 64) and the data D (eq. 111). The ballot nonce ξ_B is not part of it: it "should not be
/// published" (§3.6.7 p.51).
/// </summary>
public class DecryptedChallengedBallot
{
    public required string BallotId { get; init; }

    /// <summary>One entry per decrypted contest, in the order the ballot lists its contests.</summary>
    public required List<DecryptedChallengedContest> Contests { get; init; }
}

/// <summary>One decrypted contest of a challenged ballot, keyed by its label.</summary>
public class DecryptedChallengedContest
{
    public required string ContestId { get; init; }

    /// <summary>The selectable options, keyed by their labels, in manifest order.</summary>
    public required List<DecryptedChallengedField> Choices { get; init; }

    /// <summary>The supplemental fields the contest declares (§3.3.9), keyed by their labels, in manifest order.</summary>
    public required List<DecryptedChallengedField> SupplementalFields { get; init; }

    /// <summary>The contest data field (§3.3.10), exactly where the contest declares one; null otherwise.</summary>
    public required DecryptedChallengedContestData? ContestData { get; init; }
}

/// <summary>One verifiable field of a decrypted challenged contest: its label, σ and ξ_{i,j}.</summary>
public class DecryptedChallengedField
{
    /// <summary>The option's (or supplemental field's) label in the manifest.</summary>
    public required string Id { get; init; }

    /// <summary>σ_{i,j}, the plaintext the field encrypts (eq. 109).</summary>
    public required int Value { get; init; }

    /// <summary>ξ_{i,j} = H_q(H_I; 0x21, i, j, ξ_B) (eq. 33), the nonce of (α_{i,j}, β_{i,j}).</summary>
    public required IntegerModQ EncryptionNonce { get; init; }
}

/// <summary>A decrypted contest data field of a challenged ballot: ξ (eq. 64) and D (eq. 111).</summary>
public class DecryptedChallengedContestData
{
    /// <summary>ξ = H_q(H_I; 0x25, ind_c(Λ), ξ_B) (eq. 64), the nonce of (C_0, C_1).</summary>
    public required IntegerModQ EncryptionNonce { get; init; }

    /// <summary>D = C_{1,1} ⊕ k_1 ‖ ... ‖ C_{1,b_Λ} ⊕ k_{b_Λ} (eq. 111), 32·b_Λ bytes.</summary>
    public required byte[] Data { get; init; }

    /// <summary>
    /// The string <see cref="ContestDataEncoding.Encode"/> wrote into <see cref="Data"/>; throws
    /// <see cref="FormatException"/> if the device used another encoding.
    /// </summary>
    public string DecodeText() => ContestDataEncoding.Decode(Data);
}

/// <summary>
/// A challenged ballot as the guardians and the administrator decrypt it (§3.6.7): the ballot, its
/// H_I recomputed from H_E and id_B, and its encrypted nonce.
/// </summary>
internal sealed class ChallengedBallotStatement
{
    public required EncryptedBallot Ballot { get; init; }

    /// <summary>H_I, recomputed from H_E and the ballot's id_B (eq. 32).</summary>
    public required SelectionEncryptionIdentifierHash SelectionEncryptionIdentifierHash { get; init; }

    public EncryptedBallotNonce Nonce => Ballot.EncryptedBallotNonce;

    public string Description => $"challenged ballot {Ballot.Id}";

    /// <summary>
    /// <paramref name="ballot"/> as a challenged ballot of <paramref name="encryptionRecord"/>'s
    /// election. Throws <see cref="ArgumentException"/> if the ballot is not recorded as challenged
    /// (decrypting a cast ballot's nonce would reveal its votes), is a pre-encrypted ballot's record
    /// (<see cref="EncryptedBallot.IsPreEncrypted"/>: always a cast ballot's, §4.3.1), is malformed
    /// (<see cref="BallotStructure"/>, which also requires C_ξB with a 32-byte C_ξB,1), or its H_I is
    /// not H(H_E; 0x20, id_B) (Verification 5.B), since every hash of the decryption is keyed with H_I.
    /// Every check reads the ballot object it is given, so it cannot tell a cast ballot copied (under
    /// its own or a new string id) and marked challenged from a challenged one; the status check is a
    /// sanity check only. The guardian's authorization check against the published record's cast
    /// ballots, on id_B, H_I and C_ξB,0 (<see cref="IPublishedCastBallots"/>, user decision Q31), runs
    /// before this and is what refuses such a copy.
    /// </summary>
    public static ChallengedBallotStatement For(EncryptionRecord encryptionRecord, EncryptedBallot ballot)
    {
        ArgumentNullException.ThrowIfNull(encryptionRecord);
        ArgumentNullException.ThrowIfNull(ballot);

        if (ballot.Status != BallotStatus.Challenged)
        {
            throw new ArgumentException($"Ballot {ballot.Id} is recorded as {ballot.Status}, not as challenged; only a challenged ballot's nonce is decrypted (§3.6.7).", nameof(ballot));
        }

        // A pre-encrypted ballot's record is a cast ballot's (§4.3.1): its contests are combined
        // vectors with summed nonces, which eq. (33) does not open. A pre-encrypted ballot that is not
        // cast is opened from its released nonces (Verification 18), never through this path.
        if (ballot.IsPreEncrypted)
        {
            throw new ArgumentException($"Ballot {ballot.Id} is a pre-encrypted ballot's record; its nonce is not decrypted as a challenged ballot's (§3.6.7). An uncast pre-encrypted ballot is published with its nonces (§4.3, Verification 18).", nameof(ballot));
        }

        if (BallotStructure.FindViolation(ballot, encryptionRecord.Manifest) is string violation)
        {
            throw new ArgumentException($"Ballot {ballot.Id} is malformed, so its nonce is not decrypted: {violation}", nameof(ballot));
        }

        var selectionHash = new SelectionEncryptionIdentifierHash(encryptionRecord.ExtendedBaseHash, ballot.SelectionEncryptionIdentifier);
        if (!((byte[])selectionHash).AsSpan().SequenceEqual((byte[])ballot.SelectionEncryptionIdentifierHash))
        {
            throw new ArgumentException($"Ballot {ballot.Id}'s H_I is not H(H_E; 0x20, id_B) (Verification 5.B), so its nonce is not decrypted.", nameof(ballot));
        }

        return new ChallengedBallotStatement
        {
            Ballot = ballot,
            SelectionEncryptionIdentifierHash = selectionHash,
        };
    }

    /// <summary>
    /// What must hold of C_ξB before anyone computes a partial decryption with it. Throws
    /// <see cref="TallyDecryptionException"/> naming no guardian: the fault is the ballot's.
    /// <list type="number">
    /// <item>C_ξB,0 is in Z_p^r: 0 &lt; C_ξB,0 &lt; p and C_ξB,0^q mod p = 1. The spec does not state
    /// this check; it is the library hardening S6 made for contest data's C_0, which has the same
    /// shape. The eq. (38) proof does not exclude non-members: C_ξB,0 = 0 passes it with a_B = 0 and
    /// makes every m_i zero, and C_ξB,0 = -g^ξ-hat passes it whenever c_B is even, after which
    /// m_i = C_ξB,0^{ẑ_i} leaks the parity of each guardian's share ẑ_i (p ≡ 3 mod 4).</item>
    /// <item>§3.6.7 p.52: the Schnorr proof C_ξB,2 holds: a_B = g^{v_B}·C_ξB,0^{c_B} and
    /// c_B = H_q(H_I; 0x23, a_B, C_ξB,0, C_ξB,1) (eq. 38). "Only if the proof is verified as correct"
    /// does a guardian decrypt.</item>
    /// </list>
    /// </summary>
    public void RequireDecryptable(string who)
    {
        // IsMember also rejects 0, and raises C_ξB,0 to q as a BigInteger, never as a (zero) IntegerModQ.
        if (!SubgroupMembership.IsMember(Nonce.C0))
        {
            throw new TallyDecryptionException(null,
                $"C_ξB,0 of {Description}'s encrypted nonce is not in the order-q subgroup Z_p^r (it must satisfy 0 < C_ξB,0 < p and C_ξB,0^q mod p = 1); {who} does not decrypt it.");
        }

        if (!BallotNonceEncryption.ProofHolds(SelectionEncryptionIdentifierHash, Nonce))
        {
            throw new TallyDecryptionException(null,
                $"The Schnorr proof C_ξB,2 of {Description}'s encrypted nonce does not verify (eq. 38: c_B = H_q(H_I; 0x23, g^v_B·C_ξB,0^c_B, C_ξB,0, C_ξB,1)); {who} does not decrypt it (§3.6.7).");
        }
    }
}
