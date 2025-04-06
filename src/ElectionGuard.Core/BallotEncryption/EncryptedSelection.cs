using ElectionGuard.Core.Crypto;

namespace ElectionGuard.Core.BallotEncryption;

public record EncryptedSelection
{
    public required string ChoiceId { get; init; }
    public required IntegerModP Alpha { get; init; }
    public required IntegerModP Beta { get; init; }
    public required ChallengeResponsePair[] Proof { get; init; }
    public IntegerModQ? SelectionEncryptionNonce { get; init; }
}

public record ChallengeResponsePair
{
    public IntegerModQ Challenge { get; init; }
    public IntegerModQ Response { get; init; }
}
