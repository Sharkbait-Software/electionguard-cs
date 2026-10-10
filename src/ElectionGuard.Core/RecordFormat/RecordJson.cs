using ElectionGuard.Core.RecordFormat.Protobuf;
using ElectionGuard.Core.Serialization;
using Google.Protobuf;
using Google.Protobuf.Reflection;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace ElectionGuard.Core.RecordFormat;

/// <summary>
/// The JSON representation (design §5.5): every <c>.jsonl</c> line is one message in the proto3 JSON
/// mapping, written by Google.Protobuf's <see cref="JsonFormatter"/> and read by its
/// <see cref="JsonParser"/>. Only the parsed structure is defined, never the text: JSON bytes are
/// never hashed, and a reader hashes the canonical protobuf encoding of what it parsed.
/// <para>Writing: members in field-number order, compact (the formatter's spaced output re-written
/// through <see cref="Utf8JsonWriter"/>, with the relaxed encoder so that base64's '+' is not
/// escaped), one line per message. Content this library does not understand (unknown fields, an
/// undeclared enum value) has no JSON form, so it is refused as <c>R.version</c> rather than dropped
/// (§5.1).</para>
/// <para>Reading: the mapping's parser rejects unknown members by default, and it accepts duplicate
/// and aliased members, so before it runs the line is refused as <c>R.encoding</c> if it is not
/// well-formed UTF-8 text or names a member twice (<see cref="StrictJson.RejectAmbiguity"/>), names
/// one field by both its JSON name and its proto name, or sets two members of one oneof (a
/// <c>RecordItem</c> line with two items, which a last-wins parse would hide from D5). An unknown
/// member, or an enum value name this library does not declare, is <c>R.encoding</c> for a record of
/// this library's minor and <c>R.version</c> for a newer one (§7: neither can be turned into
/// canonical bytes without its number). The parsed message
/// is then encoded canonically, and the caller runs the canonicality check on those bytes (D1-D6:
/// widths, enums, timestamps, the one-member envelope).</para>
/// </summary>
internal static class RecordJson
{
    /// <summary>The longest line a reader accepts: base64 makes a 64 MiB item about 86 MiB of text.</summary>
    public const int MaxLineLength = 128 << 20;

    private static readonly JsonFormatter Formatter = new(JsonFormatter.Settings.Default.WithFormatDefaultValues(false));

    private static readonly JsonParser Parser = new(JsonParser.Settings.Default);

    private static readonly JsonWriterOptions CompactWriter = new()
    {
        Indented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        SkipValidation = true,
    };

    /// <summary>
    /// The JSON line (without its line feed) of the canonical item <paramref name="item"/>. Throws
    /// <c>R.version</c> if <paramref name="check"/> found content this library does not understand.
    /// </summary>
    public static byte[] FormatItem(ReadOnlySpan<byte> item, CanonicalCheck check)
    {
        if (check.HasUnknownContent)
        {
            throw RecordCodes.Failure(RecordCodes.Version, "The item holds content of a newer format minor (an unknown field, item type or enum value), which the proto3 JSON mapping cannot carry; convert it with a newer library (design §5.1).");
        }

        return Compact(Formatter.Format(RecordItem.Parser.ParseFrom(item.ToArray())));
    }

    /// <summary>The JSON line of a segment header.</summary>
    public static byte[] FormatSegmentHeader(SegmentHeader header) => Compact(Formatter.Format(header));

    /// <summary>
    /// The canonical bytes of the <c>RecordItem</c> on the line <paramref name="line"/>, for a record
    /// of format minor <paramref name="recordFormatMinor"/>; throws <c>R.encoding</c> or
    /// <c>R.version</c> as described on the class.
    /// </summary>
    public static byte[] ParseItem(ReadOnlySpan<byte> line, ushort recordFormatMinor) =>
        Parse<RecordItem>(line, RecordItem.Descriptor, recordFormatMinor).ToByteArray();

    /// <summary>The canonical bytes of the segment header on the first line of a <c>.jsonl</c> segment.</summary>
    public static byte[] ParseSegmentHeader(ReadOnlySpan<byte> line, ushort recordFormatMinor) =>
        Parse<SegmentHeader>(line, SegmentHeader.Descriptor, recordFormatMinor).ToByteArray();

    private static T Parse<T>(ReadOnlySpan<byte> line, MessageDescriptor descriptor, ushort recordFormatMinor) where T : IMessage, new()
    {
        string text;
        try
        {
            StrictJson.RejectAmbiguity(line);
            using var document = JsonDocument.Parse(line.ToArray());
            RejectAliasesAndOneofs(document.RootElement, descriptor, recordFormatMinor);
            text = Encoding.UTF8.GetString(line);
        }
        catch (JsonException ex)
        {
            throw RecordCodes.Failure(RecordCodes.Encoding, $"The line is not one unambiguous JSON object: {ex.Message}");
        }

        try
        {
            return Parser.Parse<T>(text);
        }
        catch (Exception ex) when (ex is InvalidProtocolBufferException or InvalidJsonException or FormatException or ArgumentException)
        {
            throw RecordCodes.Failure(RecordCodes.Encoding, $"The line is not a {descriptor.Name} in the proto3 JSON mapping: {ex.Message}");
        }
    }

    /// <summary>
    /// Walks the JSON value against the message descriptor: refuses a field named twice (by its JSON
    /// and its proto name), two members of one oneof, and an unknown member or enum value name (as
    /// described on the class).
    /// </summary>
    private static void RejectAliasesAndOneofs(JsonElement element, MessageDescriptor descriptor, ushort recordFormatMinor)
    {
        if (descriptor.FullName == Google.Protobuf.WellKnownTypes.Timestamp.Descriptor.FullName || element.ValueKind != JsonValueKind.Object)
        {
            // A Timestamp is an RFC 3339 string; anything else of the wrong kind is the parser's to refuse.
            return;
        }

        var fields = new Dictionary<int, string>();
        var oneofs = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var member in element.EnumerateObject())
        {
            var field = descriptor.Fields.InDeclarationOrder().FirstOrDefault(f => f.JsonName == member.Name || f.Name == member.Name);
            if (field is null)
            {
                bool newer = recordFormatMinor > RecordFormatVersion.Library.Minor;
                throw RecordCodes.Failure(newer ? RecordCodes.Version : RecordCodes.Encoding,
                    $"\"{member.Name}\" is not a member of {descriptor.Name}{(newer ? "; the record is of a newer format minor, whose fields only the protobuf representation can carry to this reader (design §7)" : "")}.");
            }

            if (!fields.TryAdd(field.FieldNumber, member.Name))
            {
                throw RecordCodes.Failure(RecordCodes.Encoding, $"{descriptor.Name} names field {field.Name} twice, as \"{fields[field.FieldNumber]}\" and \"{member.Name}\" (design §5.5).");
            }

            if (field.RealContainingOneof is { } oneof && !oneofs.TryAdd(oneof.Name, member.Name))
            {
                throw RecordCodes.Failure(RecordCodes.Encoding, $"{descriptor.Name} sets two members of oneof {oneof.Name}, \"{oneofs[oneof.Name]}\" and \"{member.Name}\" (design §5.5).");
            }

            if (field.FieldType == FieldType.Enum)
            {
                var values = field.IsRepeated && member.Value.ValueKind == JsonValueKind.Array ? member.Value.EnumerateArray().ToList() : [member.Value];
                foreach (var value in values)
                {
                    // A name this library does not declare is a value added by a newer minor (§7), or
                    // damage; a number is the parser's, and the canonicality check judges it (D2).
                    if (value.ValueKind == JsonValueKind.String && field.EnumType.FindValueByName(value.GetString()!) is null)
                    {
                        bool newer = recordFormatMinor > RecordFormatVersion.Library.Minor;
                        throw RecordCodes.Failure(newer ? RecordCodes.Version : RecordCodes.Encoding,
                            $"\"{value.GetString()}\" is not a value of {field.EnumType.Name} ({descriptor.Name}.{field.Name}){(newer ? "; the record is of a newer format minor, whose enum values only the protobuf representation can carry to this reader (design §7)" : "")}.");
                    }
                }

                continue;
            }

            if (field.FieldType != FieldType.Message)
            {
                continue;
            }

            if (field.IsRepeated && member.Value.ValueKind == JsonValueKind.Array)
            {
                foreach (var entry in member.Value.EnumerateArray())
                {
                    RejectAliasesAndOneofs(entry, field.MessageType, recordFormatMinor);
                }
            }
            else
            {
                RejectAliasesAndOneofs(member.Value, field.MessageType, recordFormatMinor);
            }
        }
    }

    private static byte[] Compact(string json)
    {
        using var document = JsonDocument.Parse(json);
        var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, CompactWriter))
        {
            document.RootElement.WriteTo(writer);
        }

        return buffer.ToArray();
    }
}
