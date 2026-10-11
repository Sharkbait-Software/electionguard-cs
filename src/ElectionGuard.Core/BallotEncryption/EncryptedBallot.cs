using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.BallotEncryption;

public class EncryptedBallot
{
    public required string Id { get; init; }
    public required SelectionEncryptionIdentifier SelectionEncryptionIdentifier { get; init; }
    public required SelectionEncryptionIdentifierHash SelectionEncryptionIdentifierHash { get; init; }
    public required string BallotStyleId { get; init; }
    public required List<EncryptedContest> Contests { get; init; }
    public required ConfirmationCode ConfirmationCode { get; init; }

    /// <summary>
    /// The chaining field B_C the confirmation code was computed with (§3.4.4; eq. 71): 36 bytes,
    /// 0x00000000 || H_DI under no chaining (eq. 73), 0x00000001 || H_{j-1} for the j-th ballot on its
    /// device under simple chaining (eq. 76). Verification 8.B recomputes H_C from it, and 8.D/8.E
    /// compare it with the field the device and the ballot's place in its device's chain imply
    /// (13.B: "B_C is the chaining field for ballot B"). It is not secret and adds no hash input.
    /// <see cref="Verify.BallotStructure"/> requires it to be 36 bytes. JSON: <c>chainingField</c>;
    /// protobuf: field 11.
    /// </summary>
    public required ChainingField ChainingField { get; init; }

    /// <summary>
    /// The encrypted ballot nonce C_ξB (§3.3.4, eqs. 34-38): "every ElectionGuard ballot contains an
    /// encryption of the ballot nonce" to the ballot data encryption key K-hat. The guardians decrypt
    /// it only for a challenged ballot (§3.6.7), and derive from ξ_B the encryption nonces they
    /// release. It is not an input to any contest hash or to the confirmation code (eqs. 70, 71).
    /// <see cref="Verify.BallotStructure"/> requires it, with C_ξB,1 of exactly 32 bytes.
    /// </summary>
    public required EncryptedBallotNonce EncryptedBallotNonce { get; init; }

    /// <summary>
    /// The ballot weight W of eq. (80): a small positive integer. The encryptor writes 1. A weight
    /// below 1 is decoded as given and rejected when the ballot is tallied, and so by
    /// Verification 9 (sub-section "9.structure"); a protobuf ballot that leaves the field off the
    /// wire decodes as 0 and is rejected the same way.
    /// </summary>
    public required int Weight { get; init; }
    public required string DeviceId { get; init; }

    /// <summary>
    /// When the ballot was encrypted (§3.7: the election record holds "the date and time of the
    /// ballot encryption"), in UTC, to the millisecond, as the encryptor's clock read it (see
    /// <see cref="BallotEncryptor"/>). Optional: null when not recorded, and then left out of both
    /// encodings. It is not an input to any hash: eq. (71) takes the contest hashes and B_C only,
    /// and §3.4 p.41 leaves the date and time to optional inputs an implementation may choose
    /// (S_device of eq. 72 could carry it, as the manifest specifies). So nothing in the ballot
    /// binds it: whoever can rewrite the record can change it, and only the record's signature
    /// (§3.7) protects it. No verification checks it. In the record it is the ballot item's
    /// <c>encrypted_at</c> (a <c>google.protobuf.Timestamp</c> of whole milliseconds, decode rule D3;
    /// in the proto3 JSON mapping <c>yyyy-MM-ddTHH:mm:ss.fffZ</c>), absent when null.
    /// </summary>
    public DateTimeOffset? EncryptionTimestamp
    {
        get => _encryptionTimestamp;
        init => _encryptionTimestamp = value is { } timestamp ? RequireTimestamp(timestamp) : null;
    }

    private readonly DateTimeOffset? _encryptionTimestamp;

    /// <summary>A UTC time truncated to whole milliseconds, the precision both encodings carry.</summary>
    internal static DateTimeOffset TruncateTimestamp(DateTimeOffset time)
    {
        var utc = time.ToUniversalTime();
        return new DateTimeOffset(utc.Ticks - (utc.Ticks % TimeSpan.TicksPerMillisecond), TimeSpan.Zero);
    }

    private static DateTimeOffset RequireTimestamp(DateTimeOffset timestamp)
    {
        if (timestamp.Offset != TimeSpan.Zero || timestamp.Ticks % TimeSpan.TicksPerMillisecond != 0)
        {
            throw new ArgumentException($"An encryption timestamp is a UTC time in whole milliseconds; got {timestamp:O}.", nameof(EncryptionTimestamp));
        }

        return timestamp;
    }

    /// <summary>
    /// Present exactly on a cast pre-encrypted ballot (§4.3, §4.4), as a pre-encrypted ballot
    /// recording tool publishes it (the tool is out of this library's scope, user decision Q35; its
    /// primitives are <see cref="PreEncryption.PreEncryptionPrimitives"/>): one entry per contest, in the order of <see cref="Contests"/>, with the contest's sorted selection
    /// hashes and the selected pre-encryption vectors with their short codes. Null on a regular
    /// ballot; JSON leaves it out then, and protobuf (field 12) writes nothing, so regular ballots
    /// serialize as before.
    ///
    /// On such a ballot <see cref="Contests"/> holds the combined selection vectors with their
    /// standard proofs, so Verifications 5, 6, 7 and 9 to 11 and the tally treat it like any other
    /// ballot (§4.4: "Selection vectors generated from pre-encrypted ballots are indistinguishable
    /// from those produced by standard ElectionGuard"). Its contest hashes are eq. (115)'s and its
    /// confirmation code eq. (116)'s, computed by the encrypting tool before any selection was made,
    /// with the pre-encrypted <see cref="ChainingField"/> and <see cref="DeviceId"/>. So Verification
    /// 8 refuses it ("8.structure": "Verification 8 is only used for regular ElectionGuard
    /// ballots", p.64), and Verifications 15, 16 and 17 check it instead.
    /// </summary>
    public List<PreEncryption.PreEncryptedCastContest>? PreEncryptedContests { get; init; }

    /// <summary>Whether this is a cast pre-encrypted ballot (<see cref="PreEncryptedContests"/> present).</summary>
    public bool IsPreEncrypted => PreEncryptedContests is not null;

    private BallotStatus _status;

    /// <summary>
    /// Whether the ballot was cast, challenged or spoiled (§3.7: "the status of the ballot (cast or
    /// challenged)"; <see cref="BallotStatus.Spoiled"/> is the record's third status, user decision
    /// S10b #4). The voter decides only after the device has shown the confirmation code, so the
    /// encryptor leaves this at <see cref="BallotStatus.Unrecorded"/> and whoever receives the ballot
    /// records it once, with <see cref="RecordStatus"/>. A deserialized ballot carries whatever its
    /// record says; the init accessor exists for that, and for copies.
    ///
    /// The status is not an input to any hash: it is not covered by the confirmation code.
    /// Aggregation (<see cref="Tally.EncryptedTally.AddBallot"/>) and therefore Verification 9 count
    /// only <see cref="BallotStatus.Cast"/> ballots, skip challenged and spoiled ones, and reject a
    /// ballot with no recorded status. Every ballot in the record was submitted, whatever its status,
    /// so Verifications 5 to 8 apply to it and its contests count for 11.D.
    /// </summary>
    public BallotStatus Status
    {
        get => _status;
        init => _status = value;
    }

    /// <summary>
    /// Records what became of the ballot: cast, challenged or spoiled. It can be recorded once: a
    /// ballot whose status is already recorded throws <see cref="InvalidOperationException"/>, so a
    /// challenged ballot, whose nonces are about to be revealed, can never become a cast one, and
    /// neither can a spoiled one.
    /// </summary>
    public void RecordStatus(BallotStatus status)
    {
        if (status is not (BallotStatus.Cast or BallotStatus.Challenged or BallotStatus.Spoiled))
        {
            throw new ArgumentOutOfRangeException(nameof(status), status, "A ballot is recorded as cast, challenged or spoiled.");
        }

        if (_status != BallotStatus.Unrecorded)
        {
            throw new InvalidOperationException($"Ballot {Id} is already recorded as {_status}; a ballot's status is recorded once and is final.");
        }

        _status = status;
    }
}

/// <summary>
/// The status of a ballot (§3.7). The numeric values are part of the protobuf encodings and equal
/// the election record's <c>BallotStatus</c> enum numbers (EGRF v2); <see cref="Unrecorded"/> is 0
/// so that a ballot whose record leaves the status out is never read as cast.
/// </summary>
public enum BallotStatus
{
    /// <summary>
    /// In memory only: no decision has been recorded yet (the encryptor's output). Never valid in a
    /// record, and a serialized ballot that carries it cannot be tallied ("9.structure"). Was
    /// <c>NotSubmitted</c>; renamed because anything in the record was by definition submitted
    /// (user decision S10b #4).
    /// </summary>
    Unrecorded = 0,

    /// <summary>Cast: included in the tally (Verification 9 "all cast ballots").</summary>
    Cast = 1,

    /// <summary>
    /// Challenged (spoiled for audit): never tallied; decrypted and published instead (§3.6.7). Only
    /// a challenged ballot's nonce is decrypted (<see cref="Tally.TallyGuardian.DecryptBallotNonce"/>), and
    /// the guardians decide that from the published record's cast ballots, not from this status (user
    /// decision Q31: a status is the requester's claim).
    /// </summary>
    Challenged = 2,

    /// <summary>
    /// Submitted but neither cast nor challenged, for example a ballot the voter abandoned (user
    /// decision S10b #4: "Anything not cast or challenged can probably be considered Spoiled").
    /// It stays in its device's chain, counts as submitted for Verifications 5.A and 11.D, and is
    /// checked by Verifications 5 to 8 like any ballot. It is never tallied, and it is not decrypted
    /// by this library's paths: the nonce path and Verifications 13 and 14 accept only a challenged
    /// ballot. That status test reads the status the requester states, so it is a sanity check, not
    /// a protection. The protection is the guardian's own view of the published record
    /// (<see cref="ElectionGuard.Core.Tally.IPublishedCastAndSpoiledBallots"/>; user decision "Refuse
    /// spoiled too", 2026-10-09): a request whose id_B, H_I or C_ξB,0 matches a spoiled ballot, as
    /// one relabelled challenged does, is refused (<see cref="ElectionGuard.Core.Tally.BallotNonceDecryptionRefusal.SpoiledBallot"/>).
    /// The recorded status itself is protected by the election record's section seal and signatures
    /// (S10b-6 onward).
    /// </summary>
    Spoiled = 3,
}

public record EncryptedContest
{
    public required string Id { get; init; }

    /// <summary>One encryption, with its range proof, per selectable option.</summary>
    public required List<EncryptedSelection> Choices { get; init; }

    /// <summary>
    /// One encryption, with its range proof, per supplemental field the manifest declares for the
    /// contest (§3.3.9), in manifest order; empty when it declares none. Each is keyed by its label
    /// and treated like an option (§3.1.3 p.19): its nonce is xi_{i,j} with its own option index j
    /// (eq. 33), and its proof challenge hashes that index (eq. 59).
    /// </summary>
    public required List<EncryptedSupplementalField> SupplementalFields { get; init; }

    /// <summary>
    /// The contest selection-limit range proof (§3.3.8, eq. 62), over 0..L, of the combined
    /// ciphertext of s + w + L*overvote + undervote indicator (user decision Q15): the product of
    /// the selections, of the write-in count, of the overvote indicator raised to L (§3.3.9 p.39 and
    /// footnote 42) and of the undervote indicator, each field only when the contest declares it.
    /// With no field declared, that is the plain aggregate of eq. (62).
    /// </summary>
    public required ChallengeResponsePair[] Proofs { get; init; }

    /// <summary>
    /// Present exactly when the contest declares an undervote difference count u: a one-value
    /// range proof (Note 3.4, the singleton set {L}) that the encryption of
    /// s + w + L*overvote + u (the overvote term when the indicator is declared) encrypts L
    /// (§3.3.9 p.38; user decision Q15). The spec gives no challenge format for it; see
    /// <see cref="BallotEncryptor"/>. Null otherwise.
    /// </summary>
    public ChallengeResponsePair[]? UndervoteDifferenceProof { get; init; }

    /// <summary>
    /// Present exactly when the contest declares a null-vote indicator: a range proof over 0..L
    /// (L + 1 pairs) that the encryption of s + w + L*overvote + L*null lies in 0..L (the overvote
    /// term when the contest declares that indicator), which enforces the indicator "just as the
    /// validity of the encrypted overvote indicator" (§3.3.9 p.39; user decisions Q15, Q17). The
    /// spec gives no challenge format for it; see <see cref="BallotEncryptor"/>. Null otherwise.
    /// </summary>
    public ChallengeResponsePair[]? NullVoteProof { get; init; }

    /// <summary>
    /// The encrypted contest data field (§3.3.10): present exactly when the manifest declares contest
    /// data for the contest (<see cref="Contest.ContestDataBlocks"/> b_Λ >= 1), with C_1 of exactly
    /// 32·b_Λ bytes, and hashed into the contest hash (eq. 70). Null otherwise.
    /// <see cref="Verify.BallotStructure"/> enforces both.
    /// </summary>
    public required EncryptedContestData? ContestData { get; init; }
    public required ContestHash ContestHash { get; init; }
}
