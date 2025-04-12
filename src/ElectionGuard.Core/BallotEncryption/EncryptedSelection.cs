using ElectionGuard.Core.Crypto;
using ProtoBuf;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;

namespace ElectionGuard.Core.BallotEncryption;

public record EncryptedSelection : EncryptedValueWithProofs
{
    [JsonPropertyName("choice_id")]
    public required string ChoiceId { get; init; }
}

public record ChallengeResponsePair
{
    [JsonPropertyName("c")]
    public IntegerModQ Challenge { get; init; }
    [JsonPropertyName("v")]
    public IntegerModQ Response { get; init; }
}

public record EncryptedValueWithProofs
{
    [JsonPropertyName("alpha")]
    public required IntegerModP Alpha { get; init; }
    [JsonPropertyName("beta")]
    public required IntegerModP Beta { get; init; }
    [JsonIgnore]
    public IntegerModQ? EncryptionNonce { get; init; }

    [JsonPropertyName("proof")]
    public required ChallengeResponsePair[] Proofs { get; init; }

    public static implicit operator EncryptedValue(EncryptedValueWithProofs value)
    {
        return new EncryptedValue
        {
            Alpha = value.Alpha,
            Beta = value.Beta,
            EncryptionNonce = value.EncryptionNonce
        };
    }

    public EncryptedValue ToEncryptedValue()
    {
        return new EncryptedValue
        {
            Alpha = Alpha,
            Beta = Beta,
            EncryptionNonce = EncryptionNonce
        };
    }
}

public struct EncryptedValue
{
    [JsonPropertyName("alpha")]
    public required IntegerModP Alpha { get; init; }
    [JsonPropertyName("beta")]
    public required IntegerModP Beta { get; init; }

    [JsonIgnore]
    public IntegerModQ? EncryptionNonce { get; init; }
}