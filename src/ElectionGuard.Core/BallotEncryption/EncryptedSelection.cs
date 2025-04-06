using ElectionGuard.Core.Crypto;

namespace ElectionGuard.Core.BallotEncryption;

public record EncryptedSelection : EncryptedValueWithProofs
{
    public required string ChoiceId { get; init; }
}

public record ChallengeResponsePair
{
    public IntegerModQ Challenge { get; init; }
    public IntegerModQ Response { get; init; }
}

public record EncryptedValueWithProofs
{
    public required EncryptedValue Value { get; init; }
    public required ChallengeResponsePair[] Proofs { get; init; }
}

public struct EncryptedValue
{
    public required IntegerModP Alpha { get; init; }
    public required IntegerModP Beta { get; init; }
    public IntegerModQ? EncryptionNonce { get; init; }
}