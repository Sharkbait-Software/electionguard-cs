using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.Serialization.Converters;
using System.Text.Json;

namespace ElectionGuard.Core.Serialization;

/// <summary>
/// JSON for pre-encrypted ballots as the encrypting tool produces them (<see cref="PreEncryptedBallot"/>,
/// §4.2) and for the election record of uncast ones (<see cref="PreEncryptedUncastBallot"/>, §4.3.1,
/// §4.4), in the encoding the ballot serializer uses: camelCase properties, group elements, Z_q
/// values and hashes base64. Decoding is strict: every element of Z_p and Z_q canonical
/// (<see cref="NonCanonicalEncodingException"/> otherwise), id_B, every selection hash and a
/// released ξ_B exactly 32 bytes, the chaining field 36, short codes and every required property
/// present. The shape against the manifest is Verification 16's, 18's and 19's to check.
///
/// A cast pre-encrypted ballot's record is an <see cref="BallotEncryption.EncryptedBallot"/> and is
/// written by <see cref="JsonEncryptedBallotSerializer"/> and <see cref="ProtobufEncryptedBallotSerializer"/>.
/// The encryption nonces of a pre-encrypted ballot's vectors are not written here
/// (<see cref="BallotEncryption.EncryptedValue.EncryptionNonce"/> is not serialized); an uncast
/// record releases them explicitly.
/// </summary>
public class JsonPreEncryptedBallotSerializer
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters =
        {
            new IntegerModQJsonConverter(),
            new IntegerModPJsonConverter(),
            new ConfirmationCodeJsonConverter(),
            new ContestHashJsonConverter(),
            new SelectionEncryptionIdentifierJsonConverter(),
            new SelectionEncryptionIdentifierHashJsonConverter(),
            new ChainingFieldJsonConverter(),
            new SelectionHashJsonConverter(),
            new ShortCodeJsonConverter(),
            new BallotNonceJsonConverter(),
        },
    };

    public void Serialize(Stream destination, PreEncryptedBallot ballot)
    {
        JsonSerializer.Serialize(destination, ballot, Options);
    }

    public PreEncryptedBallot? DeserializeBallot(Stream source)
    {
        return JsonSerializer.Deserialize<PreEncryptedBallot>(source, Options);
    }

    public void Serialize(Stream destination, PreEncryptedUncastBallot ballot)
    {
        JsonSerializer.Serialize(destination, ballot, Options);
    }

    public PreEncryptedUncastBallot? DeserializeUncastBallot(Stream source)
    {
        return JsonSerializer.Deserialize<PreEncryptedUncastBallot>(source, Options);
    }
}
