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
        if (descriptor.FullName == Google.Protobuf.WellKnownTypes.Timestamp.Descriptor.FullName)
        {
            RequireTimestampForm(element, descriptor);
            return;
        }

        if (element.ValueKind != JsonValueKind.Object)
        {
            // Anything else of the wrong kind is the parser's to refuse.
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

            RequirePlainForm(member.Value, field, descriptor);

            if (field.FieldType == FieldType.Enum)
            {
                var values = field.IsRepeated && member.Value.ValueKind == JsonValueKind.Array ? member.Value.EnumerateArray().ToList() : [member.Value];
                foreach (var value in values)
                {
                    // A name this library does not declare is a value added by a newer minor (§7), or
                    // damage; a number is the parser's, and the canonicality check judges it (D2).
                    // SectionType and DeviceKind are closed (NQ-7, NQ-9): no minor adds to them, so an
                    // undeclared name of either is damage at any record minor.
                    if (value.ValueKind == JsonValueKind.String && field.EnumType.FindValueByName(value.GetString()!) is null)
                    {
                        bool newer = recordFormatMinor > RecordFormatVersion.Library.Minor
                            && EgrfSchema.Instance.Enum(field.EnumType.FullName).MayGrowInAMinor;
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

    /// <summary>
    /// Design §5.5: a value has one written form where the mapping's parser would accept several
    /// (S10b-E review round 3). Bytes are standard base64 with padding and zero unused bits, nothing
    /// else (the mapping lets a parser take URL-safe and unpadded forms); an integer, enum numbers
    /// included, is a JSON number or a string in plain decimal: an optional '-', no leading zero, no
    /// fraction or exponent (the mapping lets a parser take exponent notation). Either is
    /// <c>R.encoding</c>. A null (a default) and the choice between number and string stay open, as
    /// the mapping makes them. None of these leniencies could change a hash (the canonical bytes are
    /// re-encoded), so refusing them only keeps the two reference readers, and any other, to one
    /// reading of a line.
    /// </summary>
    private static void RequirePlainForm(JsonElement value, FieldDescriptor field, MessageDescriptor descriptor)
    {
        if (value.ValueKind == JsonValueKind.Null || field.IsRepeated)
        {
            // There are no repeated scalars (schema rule S4); repeated messages are walked entry by entry.
            return;
        }

        switch (field.FieldType)
        {
            case FieldType.Bytes when value.ValueKind == JsonValueKind.String && !IsCanonicalBase64(value.GetString()!):
                throw RecordCodes.Failure(RecordCodes.Encoding, $"{descriptor.Name}.{field.Name} is not standard base64 with padding (design §5.5).");
            case FieldType.Int32 or FieldType.Int64 or FieldType.UInt32 or FieldType.UInt64 or FieldType.SInt32 or FieldType.SInt64
                or FieldType.Fixed32 or FieldType.Fixed64 or FieldType.SFixed32 or FieldType.SFixed64 or FieldType.Enum:
                string? form = value.ValueKind switch
                {
                    JsonValueKind.Number => value.GetRawText(),
                    JsonValueKind.String when field.FieldType != FieldType.Enum => value.GetString(),
                    _ => null,
                };
                if (form is not null && !IsPlainDecimal(form))
                {
                    throw RecordCodes.Failure(RecordCodes.Encoding, $"{descriptor.Name}.{field.Name} is \"{form}\", not an integer in plain decimal (design §5.5).");
                }

                break;
        }
    }

    /// <summary>
    /// Design §5.5's one written form for a <c>Timestamp</c> (S10b-F review round 2, extending the
    /// provisional rule (d)): the form the mapping's formatter writes for a value D3 allows, UTC with
    /// a <c>Z</c>, no fraction for a whole second, else exactly three digits
    /// (<c>2026-10-08T12:34:56Z</c>, <c>2026-10-08T12:34:56.789Z</c>). The mapping lets a parser take
    /// an offset and 0-9 fraction digits, so several strings name one instant; a string that does
    /// not parse, or names a value outside D3, is left to the parser and the canonicality check. A
    /// value that is not a string (a number, an object) is <c>R.encoding</c> here. Null is a default.
    /// </summary>
    private static void RequireTimestampForm(JsonElement element, MessageDescriptor descriptor)
    {
        if (element.ValueKind == JsonValueKind.Null)
        {
            return;
        }

        if (element.ValueKind != JsonValueKind.String)
        {
            throw RecordCodes.Failure(RecordCodes.Encoding, $"A {descriptor.Name} is an RFC 3339 string, not a JSON {element.ValueKind} (design §5.5).");
        }

        string text = element.GetString()!;
        Google.Protobuf.WellKnownTypes.Timestamp parsed;
        try
        {
            parsed = Parser.Parse<Google.Protobuf.WellKnownTypes.Timestamp>(JsonSerializer.Serialize(text));
        }
        catch (Exception ex) when (ex is InvalidProtocolBufferException or InvalidJsonException or FormatException or ArgumentException)
        {
            // Not a timestamp at all: the parser refuses it when the line is parsed.
            return;
        }

        if (parsed.Nanos % 1_000_000 != 0 || parsed.Seconds is < 0 or > 253402300799)
        {
            // Outside D3: the canonicality check names the rule.
            return;
        }

        string written = JsonSerializer.Deserialize<string>(Formatter.Format(parsed))!;
        if (written != text)
        {
            throw RecordCodes.Failure(RecordCodes.Encoding, $"\"{text}\" is not in the one written form of a {descriptor.Name}, \"{written}\" (design §5.5).");
        }
    }

    private static bool IsCanonicalBase64(string text)
    {
        if (text.Length % 4 != 0)
        {
            return false;
        }

        byte[] buffer = new byte[text.Length / 4 * 3];
        return Convert.TryFromBase64String(text, buffer, out int written) && Convert.ToBase64String(buffer, 0, written) == text;
    }

    private static bool IsPlainDecimal(string text)
    {
        int start = text.StartsWith('-') ? 1 : 0;
        if (text.Length == start || (text[start] == '0' && (text.Length > start + 1 || start == 1)))
        {
            return false;
        }

        for (int i = start; i < text.Length; i++)
        {
            if (text[i] is < '0' or > '9')
            {
                return false;
            }
        }

        return true;
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
