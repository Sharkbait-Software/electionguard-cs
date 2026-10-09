using ElectionGuard.Core.RecordFormat.Protobuf;
using Google.Protobuf;
using Google.Protobuf.Reflection;
using Google.Protobuf.WellKnownTypes;
using FieldType = Google.Protobuf.Reflection.FieldDescriptorProto.Types.Type;
using FieldLabel = Google.Protobuf.Reflection.FieldDescriptorProto.Types.Label;

namespace ElectionGuard.Core.RecordFormat;

/// <summary>
/// The EGRF v2 schema as the canonicality check reads it (design §4.4, "a transcribed table of field
/// numbers, types, width options and reserved numbers"): built once from the compiled descriptor of
/// proto/electionguard/egrf/v2/egrf.proto, parsed as a <see cref="FileDescriptorProto"/> with the
/// width options registered, so reserved ranges and the custom options are read exactly as
/// test/egrf/schema.json records them, plus <c>google.protobuf.Timestamp</c>.
/// </summary>
internal sealed class EgrfSchema
{
    public const string Package = "electionguard.egrf.v2";
    public const string RecordItemName = Package + ".RecordItem";
    public const string SegmentHeaderName = Package + ".SegmentHeader";
    public const string SectionTypeName = Package + ".SectionType";
    public const string TimestampName = "google.protobuf.Timestamp";

    public static EgrfSchema Instance { get; } = Build();

    private readonly Dictionary<string, MessageShape> _messages = new(StringComparer.Ordinal);
    private readonly Dictionary<string, EnumShape> _enums = new(StringComparer.Ordinal);

    public MessageShape Message(string fullName) => _messages[fullName];

    public EnumShape Enum(string fullName) => _enums[fullName];

    public IEnumerable<MessageShape> Messages => _messages.Values;

    private static EgrfSchema Build()
    {
        var registry = new ExtensionRegistry { EgrfExtensions.Width, EgrfExtensions.WidthMultiple, EgrfExtensions.Omittable };
        var parser = FileDescriptorProto.Parser.WithExtensionRegistry(registry);
        var schema = new EgrfSchema();
        foreach (var file in new[] { EgrfReflection.Descriptor.SerializedData, TimestampReflection.Descriptor.SerializedData })
        {
            var proto = parser.ParseFrom(file);
            foreach (var enumType in proto.EnumType)
            {
                var name = $"{proto.Package}.{enumType.Name}";
                schema._enums[name] = new EnumShape(name, enumType.Value.Select(x => (long)x.Number).ToHashSet());
            }

            foreach (var message in proto.MessageType)
            {
                schema.Add(proto.Package, message);
            }
        }

        return schema;
    }

    private void Add(string package, DescriptorProto message)
    {
        string fullName = $"{package}.{message.Name}";
        var fields = new Dictionary<int, FieldShape>();
        int highest = 0;
        var reserved = new List<(int Start, int EndExclusive)>();
        foreach (var field in message.Field)
        {
            var options = field.Options;
            fields[field.Number] = new FieldShape(
                field.Number,
                field.Name,
                field.Type,
                field.Label == FieldLabel.Repeated,
                field.TypeName.TrimStart('.'),
                options?.GetExtension(EgrfExtensions.Width) ?? 0,
                options?.GetExtension(EgrfExtensions.WidthMultiple) ?? 0,
                options?.GetExtension(EgrfExtensions.Omittable) ?? false,
                field.HasOneofIndex);
            highest = Math.Max(highest, field.Number);
        }

        foreach (var range in message.ReservedRange)
        {
            reserved.Add((range.Start, range.End));
            highest = Math.Max(highest, range.End - 1);
        }

        _messages[fullName] = new MessageShape(fullName, message.Name, fields, highest, reserved);
    }
}

internal sealed record MessageShape(string FullName, string Name, IReadOnlyDictionary<int, FieldShape> Fields, int HighestNumber, IReadOnlyList<(int Start, int EndExclusive)> Reserved)
{
    public bool IsRecordItem => FullName == EgrfSchema.RecordItemName;

    public bool IsReserved(int number) => Reserved.Any(r => number >= r.Start && number < r.EndExclusive);
}

internal sealed record FieldShape(int Number, string Name, FieldType Type, bool Repeated, string TypeName, uint Width, uint WidthMultiple, bool Omittable, bool InOneof)
{
    /// <summary>The wire type of this field (W3): VARINT for numbers, bools and enums; LEN otherwise.</summary>
    public int WireType => Type is FieldType.String or FieldType.Bytes or FieldType.Message ? 2 : 0;

    /// <summary>Implicit presence (W2): a scalar, string or bytes field outside a oneof.</summary>
    public bool ImplicitPresence => Type != FieldType.Message && !InOneof;

    public bool HasWidth => Width != 0 || WidthMultiple != 0;
}

internal sealed record EnumShape(string FullName, IReadOnlySet<long> Values)
{
    /// <summary>
    /// D2: a declared, non-zero member. <c>SectionType</c> also admits the vendor range
    /// 32768-65533 (design §4.3).
    /// </summary>
    public bool IsDeclaredNonZero(long value) =>
        value != 0 && (Values.Contains(value) || (FullName == EgrfSchema.SectionTypeName && value is >= RecordSections.FirstVendorType and <= RecordSections.LastVendorType));
}
