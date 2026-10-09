using ElectionGuard.Core.RecordFormat.Protobuf;
using Google.Protobuf;
using Google.Protobuf.Reflection;
using System.Collections;
using System.Text;
using FieldType = Google.Protobuf.Reflection.FieldDescriptorProto.Types.Type;

namespace ElectionGuard.Core.RecordFormat;

/// <summary>
/// The outcome of a canonicality check (design §4.4). <see cref="Rule"/> names the profile rule that
/// failed ("W1".."W8", "D1".."D6"; for a signed statement "R.attestation" or "R.signature"), null
/// when canonical. <see cref="HasUnknownContent"/> is set when the record's format minor is newer
/// than this library's and the item carries content this library does not understand (unknown
/// fields, an unknown item type, an undeclared enum value): it is canonical as far as this reader
/// can tell, digested as stored and reported (design §7), not a failure.
/// </summary>
public readonly record struct CanonicalCheck(bool IsCanonical, string? Rule, bool HasUnknownContent, string? Message = null)
{
    internal static CanonicalCheck Pass(bool unknown) => new(true, null, unknown);

    internal static CanonicalCheck Fail(string rule, string message) => new(false, rule, false, message);
}

/// <summary>
/// The EGRF v2 canonical protobuf profile check (design §4.2-§4.4): whether stored bytes are the
/// one canonical encoding of a <c>RecordItem</c> (or <c>SegmentHeader</c>) under the normative
/// schema. Two conformant methods are implemented:
/// <list type="bullet">
/// <item><b>Method A, the wire walk</b> (the normative reference): walks the bytes against the
/// schema table (<see cref="EgrfSchema"/>) checking W1-W8, including W6's rule for unknown fields
/// in a record of a newer format minor (after every known field, ascending, numbered above every
/// declared or reserved number, VARINT or LEN only, a VARINT never 0), then D1-D5 on the decoded
/// known values.</item>
/// <item><b>Method B, parse, re-serialize, compare</b>: parses with the generated code (discarding
/// unknown fields when the record's minor is not newer than this library's, which folds "no unknown
/// field" into the comparison; keeping them otherwise), applies D1-D5 by reflection, re-serializes
/// and compares byte for byte; for a newer minor, Method A's unknown-field rule then runs, because
/// C# writes unknown fields back in the order read (design §4.4).</item>
/// </list>
/// <see cref="Check"/> runs Method B, and on a rejection Method A to name the rule. Range (a value
/// ≥ p or ≥ q) is not a profile rule (user decision #11): the verifier reports it (design §4.8).
/// </summary>
public static class CanonicalProtobuf
{
    /// <summary>
    /// Whether <paramref name="item"/> is a canonical <c>RecordItem</c> for a record of format minor
    /// <paramref name="recordFormatMinor"/> (same major as this library).
    /// </summary>
    public static CanonicalCheck Check(ReadOnlySpan<byte> item, ushort recordFormatMinor) =>
        Check(item, EgrfSchema.RecordItemName, RecordItem.Parser, recordFormatMinor);

    /// <summary>
    /// The segment-header check of D6 (design §4.3): the header passes the item check as a
    /// <c>SegmentHeader</c>, its <c>magic</c> is "EGRF" and its <c>format_major</c> is 2. Whether
    /// it agrees with the file's path is the carrier's check. Any failure is reported as "D6" (the
    /// failure code is <c>R.container</c>), with the inner rule in the message.
    /// </summary>
    public static CanonicalCheck CheckSegmentHeader(ReadOnlySpan<byte> header, ushort recordFormatMinor)
    {
        var check = Check(header, EgrfSchema.SegmentHeaderName, SegmentHeader.Parser, recordFormatMinor);
        if (!check.IsCanonical)
        {
            return CanonicalCheck.Fail("D6", $"The segment header is not canonical ({check.Rule}): {check.Message}");
        }

        var parsed = SegmentHeader.Parser.ParseFrom(header.ToArray());
        if (parsed.Magic != "EGRF")
        {
            return CanonicalCheck.Fail("D6", $"The segment header's magic is \"{parsed.Magic}\", not \"EGRF\".");
        }

        if (parsed.FormatMajor != RecordFormatVersion.Library.Major)
        {
            return CanonicalCheck.Fail("D6", $"The segment header's format_major is {parsed.FormatMajor}, not {RecordFormatVersion.Library.Major}.");
        }

        return check;
    }

    /// <summary>
    /// The check of a signed statement (design §4.9): <paramref name="item"/> is a canonical
    /// <c>RecordItem</c> whose member is <c>device_attestation</c> (15) or <c>record_signature</c>
    /// (44), and its <c>statement</c> bytes, which the enclosing walk treats as opaque, are themselves
    /// a canonical <c>RecordItem</c> whose member is a statement type: 40-42 under
    /// <c>device_attestation</c>, 43 under <c>record_signature</c>. A failure of the outer item is its
    /// own rule; a failure of the statement is "R.attestation" or "R.signature", with the inner rule
    /// in the message.
    /// </summary>
    public static CanonicalCheck CheckSignedStatement(ReadOnlySpan<byte> item, ushort recordFormatMinor)
    {
        var outer = Check(item, recordFormatMinor);
        if (!outer.IsCanonical)
        {
            return outer;
        }

        var parsed = RecordItem.Parser.ParseFrom(item.ToArray());
        (SignedStatement? signed, string code, int[] members) = parsed.ItemCase switch
        {
            RecordItem.ItemOneofCase.DeviceAttestation => (parsed.DeviceAttestation, "R.attestation", new[] { 40, 41, 42 }),
            RecordItem.ItemOneofCase.RecordSignature => (parsed.RecordSignature, "R.signature", new[] { 43 }),
            _ => (null, "R.signature", Array.Empty<int>()),
        };

        if (signed is null)
        {
            return CanonicalCheck.Fail(code, $"The item is not a signed statement (member {(int)parsed.ItemCase}).");
        }

        var statement = signed.Statement.Span;
        var inner = Check(statement, recordFormatMinor);
        if (!inner.IsCanonical)
        {
            return CanonicalCheck.Fail(code, $"The signed statement is not a canonical RecordItem ({inner.Rule}): {inner.Message}");
        }

        int member = (int)RecordItem.Parser.ParseFrom(statement.ToArray()).ItemCase;
        if (!members.Contains(member))
        {
            return CanonicalCheck.Fail(code, $"The signed statement's member is {member}, not one of {string.Join(", ", members)}.");
        }

        return new CanonicalCheck(true, null, outer.HasUnknownContent || inner.HasUnknownContent);
    }

    private static CanonicalCheck Check(ReadOnlySpan<byte> bytes, string messageName, MessageParser parser, ushort recordFormatMinor)
    {
        bool readerOlder = recordFormatMinor > RecordFormatVersion.Library.Minor;
        var b = MethodB(bytes, messageName, parser, readerOlder);
        if (b.IsCanonical)
        {
            return b;
        }

        // Method B cannot always tell which rule failed; Method A names it.
        var a = MethodA(bytes, messageName, readerOlder);
        return a.IsCanonical ? b : a;
    }

    // ---- Method A: the wire walk ------------------------------------------------------------------

    /// <summary>
    /// Method A (design §4.4) on <paramref name="bytes"/> as the message <paramref name="messageName"/>.
    /// <paramref name="readerOlder"/>: the record's format minor is newer than this library's, so
    /// unknown fields are allowed under W6 and reported.
    /// </summary>
    internal static CanonicalCheck MethodA(ReadOnlySpan<byte> bytes, string messageName = EgrfSchema.RecordItemName, bool readerOlder = false)
    {
        var walk = new Walker(readerOlder);
        try
        {
            walk.Message(bytes, EgrfSchema.Instance.Message(messageName));
        }
        catch (ViolationException violation)
        {
            return CanonicalCheck.Fail(violation.Rule, violation.Message);
        }

        return walk.FirstDecodeViolation is { } d
            ? CanonicalCheck.Fail(d.Rule, d.Message)
            : CanonicalCheck.Pass(walk.UnknownContent);
    }

    private sealed class ViolationException(string rule, string message) : Exception(message)
    {
        public string Rule { get; } = rule;
    }

    private sealed class Walker(bool readerOlder)
    {
        public bool UnknownContent { get; private set; }

        public (string Rule, string Message)? FirstDecodeViolation { get; private set; }

        private void Decode(string rule, string message) => FirstDecodeViolation ??= (rule, message);

        private static ViolationException Fail(string rule, string message) => new(rule, message);

        public void Message(ReadOnlySpan<byte> data, MessageShape shape)
        {
            int position = 0;
            int last = 0;
            bool inUnknown = false;
            int fieldCount = 0;
            var present = new HashSet<int>();
            long seconds = 0, nanos = 0;

            while (position < data.Length)
            {
                ulong tag = ReadVarint(data, ref position, $"{shape.Name}: tag");
                if (tag > uint.MaxValue || (tag >> 3) == 0 || (tag >> 3) > 536_870_911)
                {
                    throw Fail("W3", $"{shape.Name}: tag {tag} names no valid field number.");
                }

                int number = (int)(tag >> 3);
                int wireType = (int)(tag & 7);
                fieldCount++;

                if (shape.Fields.TryGetValue(number, out var field))
                {
                    if (inUnknown)
                    {
                        throw Fail("W6", $"{shape.Name}.{field.Name} ({number}) follows an unknown field; unknown fields come after every known field.");
                    }

                    if (wireType != field.WireType)
                    {
                        throw Fail("W3", $"{shape.Name}.{field.Name} ({number}) has wire type {wireType}, not {field.WireType}.");
                    }

                    if (number < last)
                    {
                        throw Fail("W1", $"{shape.Name}.{field.Name} ({number}) follows field {last}; fields are in ascending number order.");
                    }

                    if (number == last && !field.Repeated)
                    {
                        throw Fail("W2", $"{shape.Name}.{field.Name} ({number}) appears twice; a singular field appears at most once.");
                    }

                    present.Add(number);
                    if (wireType == 0)
                    {
                        ulong value = ReadVarint(data, ref position, $"{shape.Name}.{field.Name}");
                        Scalar(shape, field, value);
                        if (shape.FullName == EgrfSchema.TimestampName)
                        {
                            if (number == 1)
                            {
                                seconds = (long)value;
                            }
                            else if (number == 2)
                            {
                                nanos = (long)value;
                            }
                        }
                    }
                    else
                    {
                        var payload = ReadLength(data, ref position, $"{shape.Name}.{field.Name}");
                        Length(shape, field, payload);
                    }
                }
                else
                {
                    Unknown(data, ref position, shape, number, wireType, last, fieldCount);
                    inUnknown = true;
                }

                last = number;
            }

            // D1: an absent width-annotated bytes field must be omittable.
            foreach (var field in shape.Fields.Values)
            {
                if (present.Contains(field.Number))
                {
                    continue;
                }

                if (field.Type == FieldType.Bytes && field.HasWidth && !field.Omittable)
                {
                    Decode("D1", $"{shape.Name}.{field.Name} ({field.Number}) is absent, but has a width and is not omittable.");
                }

                if (field.Type == FieldType.Enum && !field.Repeated)
                {
                    Decode("D2", $"{shape.Name}.{field.Name} ({field.Number}) is absent, so UNSPECIFIED, which is never valid in a record.");
                }
            }

            if (shape.FullName == EgrfSchema.TimestampName)
            {
                CheckTimestamp(seconds, nanos, Decode);
            }

            if (shape.IsRecordItem && fieldCount != 1)
            {
                Decode("D5", $"A RecordItem has exactly one field, the member of its oneof; this one has {fieldCount}.");
            }
        }

        private void Scalar(MessageShape shape, FieldShape field, ulong value)
        {
            string name = $"{shape.Name}.{field.Name} ({field.Number})";
            if (value == 0 && field.ImplicitPresence)
            {
                throw Fail("W2", $"{name} is written with its default value 0; an implicit-presence field is written only when it differs from its default.");
            }

            switch (field.Type)
            {
                case FieldType.Bool when value != 1:
                    throw Fail("W4", $"{name} is a bool written as {value}; true is the single byte 0x01.");
                case FieldType.Uint32 when value >= 1UL << 31:
                    Decode("D4", $"{name} is {value}, not below 2^31.");
                    break;
                case FieldType.Uint64 when value >= 1UL << 63:
                    Decode("D4", $"{name} is {value}, not below 2^63.");
                    break;
                case FieldType.Enum:
                    var enumShape = EgrfSchema.Instance.Enum(field.TypeName);
                    long number = (long)value;

                    // An enum is an int32 on the wire: a value in [2^31, 2^64 - 2^31) is no int32
                    // encoding (a negative one is sign-extended to 64 bits), so no later minor can
                    // declare it, and a runtime would truncate it. D2 at any reader age.
                    bool int32 = value <= int.MaxValue || value >= 0xFFFF_FFFF_8000_0000UL;
                    if (!enumShape.IsDeclaredNonZero(number))
                    {
                        if (readerOlder && number != 0 && int32)
                        {
                            UnknownContent = true;
                        }
                        else
                        {
                            Decode("D2", $"{name} is {number}, not a declared value of {enumShape.FullName}.");
                        }
                    }

                    break;
            }
        }

        private void Length(MessageShape shape, FieldShape field, ReadOnlySpan<byte> payload)
        {
            string name = $"{shape.Name}.{field.Name} ({field.Number})";
            switch (field.Type)
            {
                case FieldType.String:
                    if (payload.Length == 0 && field.ImplicitPresence)
                    {
                        throw Fail("W2", $"{name} is written empty; an implicit-presence string is written only when non-empty.");
                    }

                    if (!System.Text.Unicode.Utf8.IsValid(payload))
                    {
                        throw Fail("W8", $"{name} is not well-formed UTF-8.");
                    }

                    break;
                case FieldType.Bytes:
                    if (payload.Length == 0 && field.ImplicitPresence)
                    {
                        throw Fail("W2", $"{name} is written empty; an implicit-presence bytes field is written only when non-empty.");
                    }

                    if (field.Width != 0 && payload.Length != field.Width)
                    {
                        Decode("D1", $"{name} has {payload.Length} bytes, not {field.Width}.");
                    }

                    if (field.WidthMultiple != 0 && (payload.Length == 0 || payload.Length % field.WidthMultiple != 0))
                    {
                        Decode("D1", $"{name} has {payload.Length} bytes, not a positive multiple of {field.WidthMultiple}.");
                    }

                    break;
                case FieldType.Message:
                    Message(payload, EgrfSchema.Instance.Message(field.TypeName));
                    break;
            }
        }

        private void Unknown(ReadOnlySpan<byte> data, ref int position, MessageShape shape, int number, int wireType, int last, int fieldCount)
        {
            if (!readerOlder)
            {
                throw Fail("W6", $"{shape.Name} has field {number}, which the schema of the record's format minor does not define.");
            }

            if (shape.IsRecordItem)
            {
                // An item type this reader does not know: the RecordItem's one field (D5 counts it).
                if (shape.IsReserved(number))
                {
                    throw Fail("W6", $"RecordItem member {number} is a reserved number, never reused.");
                }

                if (wireType != 2)
                {
                    throw Fail("W3", $"RecordItem member {number} has wire type {wireType}; oneof members are messages (LEN).");
                }
            }
            else if (number <= shape.HighestNumber)
            {
                throw Fail("W6", $"{shape.Name} has unknown field {number}, not above every number the schema declares or reserves ({shape.HighestNumber}).");
            }

            if (number < last || (number == last && wireType != 2))
            {
                throw Fail("W6", $"{shape.Name}: unknown field {number} follows field {last}; unknown fields are in ascending order, and only a LEN field may repeat.");
            }

            switch (wireType)
            {
                case 0:
                    if (ReadVarint(data, ref position, $"{shape.Name}: unknown field {number}") == 0)
                    {
                        throw Fail("W2", $"{shape.Name}: unknown VARINT field {number} is 0, an explicitly written default.");
                    }

                    break;
                case 2:
                    ReadLength(data, ref position, $"{shape.Name}: unknown field {number}");
                    break;
                default:
                    throw Fail("W3", $"{shape.Name}: unknown field {number} has wire type {wireType}; only VARINT and LEN occur.");
            }

            UnknownContent = true;
        }

        private static ReadOnlySpan<byte> ReadLength(ReadOnlySpan<byte> data, ref int position, string what)
        {
            ulong length = ReadVarint(data, ref position, what + ": length");
            if (length > (ulong)(data.Length - position))
            {
                throw Fail("W5", $"{what}: length {length} runs past the end of its message ({data.Length - position} bytes remain).");
            }

            var payload = data.Slice(position, (int)length);
            position += (int)length;
            return payload;
        }

        /// <summary>A minimal varint (W4): at most 10 bytes, fitting 64 bits, no final 0x00 after a continuation.</summary>
        private static ulong ReadVarint(ReadOnlySpan<byte> data, ref int position, string what)
        {
            ulong value = 0;
            for (int i = 0; i < 10; i++)
            {
                if (position >= data.Length)
                {
                    throw Fail("W5", $"{what}: a varint runs past the end of its message.");
                }

                byte b = data[position++];
                if (i == 9 && b > 1)
                {
                    throw Fail("W4", $"{what}: a varint does not fit 64 bits.");
                }

                value |= (ulong)(b & 0x7F) << (7 * i);
                if ((b & 0x80) == 0)
                {
                    if (i > 0 && b == 0)
                    {
                        throw Fail("W4", $"{what}: a varint is not minimal (it ends in 0x00 after a continuation).");
                    }

                    return value;
                }
            }

            throw Fail("W4", $"{what}: a varint is longer than 10 bytes.");
        }
    }

    /// <summary>D3: seconds in [0, 253402300799], nanos a multiple of 1,000,000 in [0, 999,000,000].</summary>
    private static void CheckTimestamp(long seconds, long nanos, Action<string, string> decode)
    {
        if (seconds is < 0 or > 253_402_300_799)
        {
            decode("D3", $"A timestamp's seconds are {seconds}, outside 1970-01-01T00:00:00Z..9999-12-31T23:59:59Z.");
        }

        if (nanos is < 0 or > 999_000_000 || nanos % 1_000_000 != 0)
        {
            decode("D3", $"A timestamp's nanos are {nanos}, not a whole number of milliseconds in [0, 999,000,000].");
        }
    }

    // ---- Method B: parse, re-serialize, compare ---------------------------------------------------

    /// <summary>
    /// Method B (design §4.4) on <paramref name="bytes"/> as <paramref name="messageName"/>, parsed by
    /// <paramref name="parser"/>. Its failures that are not decode rules carry the rule "B" (the
    /// bytes are not what a canonical serializer writes); <see cref="Check"/> asks Method A which.
    /// </summary>
    internal static CanonicalCheck MethodB(ReadOnlySpan<byte> bytes, string messageName = EgrfSchema.RecordItemName, MessageParser? parser = null, bool readerOlder = false)
    {
        parser ??= RecordItem.Parser;
        IMessage message;
        byte[] input = bytes.ToArray();
        try
        {
            message = (readerOlder ? parser : parser.WithDiscardUnknownFields(true)).ParseFrom(input);
        }
        catch (InvalidProtocolBufferException ex)
        {
            return CanonicalCheck.Fail("B", $"The bytes do not parse: {ex.Message}");
        }

        var decode = new DecodeRules(readerOlder);
        decode.Check(message, EgrfSchema.Instance.Message(messageName));
        if (decode.First is { } d)
        {
            return CanonicalCheck.Fail(d.Rule, d.Message);
        }

        if (!message.ToByteArray().AsSpan().SequenceEqual(input))
        {
            return CanonicalCheck.Fail("B", "Re-serializing the parsed message does not give the same bytes.");
        }

        bool unknown = decode.UnknownContent;
        if (readerOlder)
        {
            // C# keeps unknown fields in the order read, so their placement and numbering (W6)
            // need Method A's branch (design §4.4).
            var a = MethodA(bytes, messageName, readerOlder: true);
            if (!a.IsCanonical)
            {
                return a;
            }

            unknown |= a.HasUnknownContent;
        }

        return CanonicalCheck.Pass(unknown);
    }

    /// <summary>D1-D5 on a parsed message, by reflection over the generated types and the schema table.</summary>
    private sealed class DecodeRules(bool readerOlder)
    {
        public (string Rule, string Message)? First { get; private set; }

        public bool UnknownContent { get; private set; }

        private void Fail(string rule, string message) => First ??= (rule, message);

        public void Check(IMessage message, MessageShape shape)
        {
            int set = 0;
            long seconds = 0, nanos = 0;
            foreach (var descriptor in message.Descriptor.Fields.InFieldNumberOrder())
            {
                var field = shape.Fields[descriptor.FieldNumber];
                string name = $"{shape.Name}.{field.Name} ({field.Number})";
                object value = descriptor.Accessor.GetValue(message);
                if (field.Repeated)
                {
                    foreach (var element in (IList)value)
                    {
                        set++;
                        Check((IMessage)element, EgrfSchema.Instance.Message(field.TypeName));
                    }

                    continue;
                }

                if (field.Type == FieldType.Message)
                {
                    if (descriptor.Accessor.HasValue(message))
                    {
                        set++;
                        Check((IMessage)value, EgrfSchema.Instance.Message(field.TypeName));
                    }

                    continue;
                }

                switch (field.Type)
                {
                    case FieldType.Bytes:
                        var bytes = (ByteString)value;
                        if (bytes.Length == 0)
                        {
                            if (field.HasWidth && !field.Omittable)
                            {
                                Fail("D1", $"{name} is absent, but has a width and is not omittable.");
                            }
                        }
                        else
                        {
                            set++;
                            if (field.Width != 0 && bytes.Length != field.Width)
                            {
                                Fail("D1", $"{name} has {bytes.Length} bytes, not {field.Width}.");
                            }

                            if (field.WidthMultiple != 0 && bytes.Length % field.WidthMultiple != 0)
                            {
                                Fail("D1", $"{name} has {bytes.Length} bytes, not a positive multiple of {field.WidthMultiple}.");
                            }
                        }

                        break;
                    case FieldType.Uint32 when (uint)value >= 1U << 31:
                        Fail("D4", $"{name} is {value}, not below 2^31.");
                        break;
                    case FieldType.Uint64 when (ulong)value >= 1UL << 63:
                        Fail("D4", $"{name} is {value}, not below 2^63.");
                        break;
                    case FieldType.Enum:
                        long number = Convert.ToInt64(value);
                        var enumShape = EgrfSchema.Instance.Enum(field.TypeName);
                        if (!enumShape.IsDeclaredNonZero(number))
                        {
                            if (readerOlder && number != 0)
                            {
                                UnknownContent = true;
                            }
                            else
                            {
                                Fail("D2", $"{name} is {number}, not a declared value of {enumShape.FullName}.");
                            }
                        }

                        break;
                    case FieldType.Int64 when shape.FullName == EgrfSchema.TimestampName:
                        seconds = (long)value;
                        break;
                    case FieldType.Int32 when shape.FullName == EgrfSchema.TimestampName:
                        nanos = (int)value;
                        break;
                }
            }

            if (shape.FullName == EgrfSchema.TimestampName)
            {
                CheckTimestamp(seconds, nanos, Fail);
            }

            if (shape.IsRecordItem && set != 1)
            {
                // Kept unknown fields (a newer minor's item type) make the one field.
                bool unknownMember = readerOlder && set == 0 && message.CalculateSize() > 0;
                if (unknownMember)
                {
                    UnknownContent = true;
                }
                else
                {
                    Fail("D5", $"A RecordItem has exactly one field, the member of its oneof; this one has {set} known.");
                }
            }
        }
    }
}
