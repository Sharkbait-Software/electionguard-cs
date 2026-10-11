using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.PreEncryption;

/// <summary>
/// §4.1 / §4.2 a pre-encrypted ballot: every selectable option of every contest on a ballot style,
/// encrypted before the voter's selections are known, with the short codes printed beside them.
/// </summary>
public record PreEncryptedBallot
{
    public required string Id { get; init; }
    public required string BallotStyleId { get; init; }
    public required SelectionEncryptionIdentifier SelectionEncryptionIdentifier { get; init; }
    public required SelectionEncryptionIdentifierHash SelectionEncryptionIdentifierHash { get; init; }

    /// <summary>§3.3.4 the ballot nonce encrypted to the other-ballot-data encryption key K-hat.</summary>
    public required EncryptedBallotNonce EncryptedBallotNonce { get; init; }

    /// <summary>The contests of the ballot style in increasing contest index order.</summary>
    public required List<PreEncryptedContest> Contests { get; init; }

    public required ChainingField ChainingField { get; init; }
    public required ConfirmationCode ConfirmationCode { get; init; }
    public required string DeviceId { get; init; }
}

/// <summary>
/// §4.1.2 one contest of a pre-encrypted ballot: a selection vector per option followed by one null
/// vector per unit of the contest's selection limit.
/// </summary>
public record PreEncryptedContest
{
    public required string ContestId { get; init; }
    public required int ContestIndex { get; init; }

    /// <summary>The option vectors in increasing option index order, then the null vectors.</summary>
    public required List<PreEncryptedSelection> Selections { get; init; }

    public required ContestHash ContestHash { get; init; }

    /// <summary>§4.4: the selection hashes as published, sorted numerically.</summary>
    public IReadOnlyList<SelectionHash> SortedSelectionHashes => Selections.Select(s => s.SelectionHash).Order().ToList();
}

/// <summary>
/// §4.1 one pre-encryption vector Ψ_{i,m}: an encryption for every option position in the contest,
/// of one at the position of the selection it represents and of zero elsewhere (all zero for a null
/// vector).
/// </summary>
public record PreEncryptedSelection
{
    /// <summary>
    /// The index j of eq. (121): the option index for an option vector; for the ℓ-th null vector,
    /// the contest's largest option index plus ℓ.
    /// </summary>
    public required int SelectionIndex { get; init; }

    /// <summary>The option this vector selects, or null for a null vector.</summary>
    public required string? ChoiceId { get; init; }

    public bool IsNullVote => ChoiceId is null;

    public required IReadOnlyList<EncryptedValue> Vector { get; init; }
    public required SelectionHash SelectionHash { get; init; }
    public required ShortCode ShortCode { get; init; }
}
