using ElectionGuard.Core.BallotEncryption;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ElectionGuard.Core.Serialization;

/// <summary>
/// The required scalar members every decoded <see cref="EncryptedBallot"/> must have: its id, its
/// ballot style, H_I, each contest's, option's and supplemental field's label, each contest data
/// field's C_1, and each pre-encrypted contest's label. Both ballot decoders run it, so a document
/// that nulls or (protobuf) leaves out one of them fails at decode time as a
/// <see cref="NonCanonicalEncodingException"/> rather than as a <see cref="NullReferenceException"/>
/// somewhere in Verifications 5-9 (the S3 and S5 carry-overs, closed in S10a).
///
/// Lists and their entries are not checked here: a null or (protobuf) missing contest, option or
/// supplemental field list, or a null entry in one, is reported by <see cref="Verify.BallotStructure"/>
/// as <c>"N.structure"</c>, as a null supplemental field list already was (S5 review), and as the
/// ballot's missing contests or options are. A protobuf document cannot tell an empty list from a
/// missing one, so the protobuf decoder reads a missing list as empty. Also left downstream, where
/// tests pin them: a null proof list (Verifications 6 and 7 report the wrong number of proofs), a
/// null device id or encrypted ballot nonce (<see cref="Verify.BallotStructure"/>).
/// </summary>
internal static class EncryptedBallotShape
{
    public static void Require(EncryptedBallot ballot)
    {
        Present(ballot.Id, "The ballot has no id.");
        string id = ballot.Id;
        Present(ballot.BallotStyleId, $"Ballot {id} names no ballot style.");
        Present(ballot.SelectionEncryptionIdentifierHash, $"Ballot {id} has no selection encryption identifier hash H_I.");
        foreach (var contest in ballot.Contests ?? [])
        {
            if (contest is null)
            {
                continue;
            }

            Present(contest.Id, $"Ballot {id} has a contest with no id.");
            foreach (var choice in contest.Choices ?? [])
            {
                if (choice is not null)
                {
                    Present(choice.ChoiceId, $"Contest {contest.Id} of ballot {id} has a selection with no option id.");
                }
            }

            foreach (var field in contest.SupplementalFields ?? [])
            {
                if (field is not null)
                {
                    Present(field.FieldId, $"Contest {contest.Id} of ballot {id} has a supplemental field with no field id.");
                }
            }

            if (contest.ContestData is { } data)
            {
                Present(data.C1, $"The contest data of contest {contest.Id} of ballot {id} has no C_1.");
            }
        }

        foreach (var contest in ballot.PreEncryptedContests ?? [])
        {
            if (contest is not null)
            {
                Present(contest.ContestId, $"Ballot {id} has a pre-encrypted contest with no id.");
            }
        }
    }

    private static void Present(object? value, string message)
    {
        if (value is null)
        {
            throw new NonCanonicalEncodingException(message);
        }
    }
}

/// <summary>
/// <see cref="EncryptedBallot.EncryptionTimestamp"/> as exactly <c>yyyy-MM-ddTHH:mm:ss.fffZ</c>
/// (UTC, milliseconds). Anything else, another offset or precision included, is a
/// <see cref="NonCanonicalEncodingException"/>.
/// </summary>
internal sealed class EncryptionTimestampJsonConverter : JsonConverter<DateTimeOffset>
{
    public const string Format = "yyyy-MM-dd'T'HH:mm:ss.fff'Z'";

    /// <summary>The length of the written form, e.g. <c>2026-10-08T12:34:56.789Z</c>.</summary>
    private const int TextLength = 24;

    public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException($"An encryption timestamp is a string of the form {Format}; got {reader.TokenType}.");
        }

        string text = reader.GetString()!;
        if (text.Length != TextLength
            ||!DateTimeOffset.TryParseExact(text, Format, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var timestamp))
        {
            throw new NonCanonicalEncodingException($"An encryption timestamp is written exactly as {Format} (UTC, milliseconds); got \"{text}\".");
        }

        return timestamp;
    }

    public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.ToUniversalTime().ToString(Format, CultureInfo.InvariantCulture));
    }
}
