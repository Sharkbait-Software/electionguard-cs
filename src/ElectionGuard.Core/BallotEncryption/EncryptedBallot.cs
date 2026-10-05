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
    /// The ballot weight W of eq. (80): a small positive integer. The encryptor writes 1. A weight
    /// below 1 is decoded as given and rejected when the ballot is tallied, and so by
    /// Verification 9 (sub-section "9.structure"); a protobuf ballot that leaves the field off the
    /// wire decodes as 0 and is rejected the same way.
    /// </summary>
    public required int Weight { get; init; }
    public required string DeviceId { get; init; }

    private BallotStatus _status;

    /// <summary>
    /// Whether the ballot was cast or challenged (§3.7: "the status of the ballot (cast or
    /// challenged)"). The voter decides only after the device has shown the confirmation code, so
    /// the encryptor leaves this at <see cref="BallotStatus.NotSubmitted"/> and whoever receives the
    /// ballot records it once, with <see cref="RecordStatus"/>. A deserialized ballot carries
    /// whatever its record says; the init accessor exists for that, and for copies.
    ///
    /// The status is not an input to any hash: it is not covered by the confirmation code.
    /// Aggregation (<see cref="Tally.EncryptedTally.AddBallot"/>) and therefore Verification 9 count
    /// only <see cref="BallotStatus.Cast"/> ballots, skip challenged ones, and reject a ballot with
    /// no recorded status. Verifications 5 to 8 apply to every submitted ballot whatever its status.
    /// </summary>
    public BallotStatus Status
    {
        get => _status;
        init => _status = value;
    }

    /// <summary>
    /// Records the voter's cast-or-challenge decision. It can be made once: a ballot whose status
    /// is already recorded throws <see cref="InvalidOperationException"/>, so a challenged ballot,
    /// whose nonces are about to be revealed, can never become a cast one.
    /// </summary>
    public void RecordStatus(BallotStatus status)
    {
        if (status is not (BallotStatus.Cast or BallotStatus.Challenged))
        {
            throw new ArgumentOutOfRangeException(nameof(status), status, "A ballot is recorded as cast or as challenged.");
        }

        if (_status != BallotStatus.NotSubmitted)
        {
            throw new InvalidOperationException($"Ballot {Id} is already recorded as {_status}; the cast-or-challenge decision is final.");
        }

        _status = status;
    }
}

/// <summary>
/// The status of a submitted ballot in the election record (§3.7). The numeric values are part of
/// the protobuf encoding; <see cref="NotSubmitted"/> is 0 so that a ballot whose record leaves the
/// status out is never read as cast.
/// </summary>
public enum BallotStatus
{
    /// <summary>No cast-or-challenge decision has been recorded. Such a ballot cannot be tallied.</summary>
    NotSubmitted = 0,

    /// <summary>Cast: included in the tally (Verification 9 "all cast ballots").</summary>
    Cast = 1,

    /// <summary>Challenged (spoiled for audit): never tallied; decrypted and published instead (§3.6.7).</summary>
    Challenged = 2,
}

public record EncryptedContest
{
    public required string Id { get; init; }
    public required List<EncryptedSelection> Choices { get; init; }
    public required ChallengeResponsePair[] Proofs { get; init; }
    public required EncryptedValueWithProofs OvervoteCount { get; init; }
    public required EncryptedValueWithProofs NullvoteCount { get; init; }
    public required EncryptedValueWithProofs UndervoteCount { get; init; }
    public required EncryptedValueWithProofs WriteInVoteCount { get; init; }
    public required EncryptedData? ContestData { get; init; }
    public required ContestHash ContestHash { get; init; }
}
