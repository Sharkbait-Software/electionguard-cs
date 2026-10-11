using ElectionGuard.Core.Crypto;
using System.Text.Json.Serialization;

namespace ElectionGuard.Core.BallotEncryption;

public record EncryptedSelection : EncryptedValueWithProofs
{
    public required string ChoiceId { get; init; }
}

/// <summary>
/// The encryption of a supplemental verifiable field (§3.3.9), with its range proof, keyed by the
/// field's label in the manifest (<see cref="Models.SupplementalField"/>).
/// </summary>
public record EncryptedSupplementalField : EncryptedValueWithProofs
{
    public required string FieldId { get; init; }
}

public record ChallengeResponsePair
{
    public IntegerModQ Challenge { get; init; }
    public IntegerModQ Response { get; init; }
}

public record EncryptedValueWithProofs
{
    public required IntegerModP Alpha { get; init; }
    public required IntegerModP Beta { get; init; }

    /// <summary>
    /// The encryption nonce, held only by the encryptor. No record item has a field for it
    /// (<c>RecordCompletenessTests</c>); the attribute keeps it out of any ad hoc JSON dump too.
    /// </summary>
    [JsonIgnore]
    public IntegerModQ? EncryptionNonce { get; init; }

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
    public required IntegerModP Alpha { get; init; }
    public required IntegerModP Beta { get; init; }

    /// <summary>The encryption nonce, held only by the encryptor (see <see cref="EncryptedValueWithProofs.EncryptionNonce"/>).</summary>
    [JsonIgnore]
    public IntegerModQ? EncryptionNonce { get; init; }
}
