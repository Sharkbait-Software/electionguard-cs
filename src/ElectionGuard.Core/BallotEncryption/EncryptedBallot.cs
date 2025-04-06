using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.BallotEncryption;

public class EncryptedBallot
{
    public required string Id { get; init; }
    public required SelectionEncryptionIdentifierHash SelectionEncryptionIdentifierHash { get; init; }
    public required string BallotStyleId { get; init; }
    public required List<EncryptedContest> Contests { get; init; }
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
}