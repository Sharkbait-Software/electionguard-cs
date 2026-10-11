using ElectionGuard.Core.RecordFormat.Protobuf;
using Google.Protobuf;
using Google.Protobuf.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using FieldType = Google.Protobuf.Reflection.FieldDescriptorProto.Types.Type;
using FieldLabel = Google.Protobuf.Reflection.FieldDescriptorProto.Types.Label;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// The schema rules of the EGRF v2 canonical protobuf profile (design document §4.2.1, rules S1-S8),
/// checked on a compiled <see cref="FileDescriptorProto"/>: the real schema's, built from
/// proto/electionguard/egrf/v2/egrf.proto, or a deliberately broken copy in the tests. Each
/// violation names its rule ("S2: ..."), so a test can assert which rule caught it.
///
/// Also the schema table (<see cref="Table"/>) written to test/egrf/schema.json: field numbers,
/// types, labels and width options per message, which the append-only rule (S6) is checked against
/// (<see cref="AppendOnlyViolations"/>) and which a reader in another language transcribes.
/// </summary>
internal static class EgrfSchemaLint
{
    public const string Package = "electionguard.egrf.v2";

    /// <summary>
    /// Bytes fields that carry variable-length data and so have no width option (S7). Any other
    /// bytes field must be annotated, so a new fixed-width field cannot be added without its width.
    /// </summary>
    public static readonly IReadOnlySet<string> VariableLengthBytes = new HashSet<string>(StringComparer.Ordinal)
    {
        "SegmentHeader.key", "ManifestFile.content", "TocEntry.key",
        "SignedStatement.statement", "SignedStatement.key_id", "SignedStatement.signer_key",
        "SignedStatement.signature", "SignedStatement.timestamp_token",
    };

    /// <summary>Messages on every ballot, whose fields keep one-byte tags (numbers 1-15; S6).</summary>
    public static readonly IReadOnlySet<string> HotMessages = new HashSet<string>(StringComparer.Ordinal)
    {
        "EncryptedBallot", "EncryptedContest", "EncryptedField", "HashedCiphertext",
    };

    private static readonly ExtensionRegistry Registry = new() { EgrfExtensions.Width, EgrfExtensions.WidthMultiple, EgrfExtensions.Omittable };

    /// <summary>The compiled schema, with its width options readable.</summary>
    public static FileDescriptorProto Compiled() =>
        FileDescriptorProto.Parser.WithExtensionRegistry(Registry).ParseFrom(EgrfReflection.Descriptor.SerializedData);

    public static List<string> Violations(FileDescriptorProto file)
    {
        var violations = new List<string>();
        if (file.Syntax != "proto3")
        {
            violations.Add($"S1: syntax is \"{file.Syntax}\", not proto3.");
        }

        if (file.Package != Package)
        {
            violations.Add($"S1: package is {file.Package}, not {Package}.");
        }

        foreach (var extension in file.Extension)
        {
            if (extension.Extendee != ".google.protobuf.FieldOptions" || extension.Number is < 50001 or > 50003)
            {
                violations.Add($"S7: extension {extension.Name} ({extension.Extendee} {extension.Number}) is not one of the profile's width options.");
            }
        }

        foreach (var enumType in file.EnumType)
        {
            CheckEnum(enumType, violations);
        }

        foreach (var message in file.MessageType)
        {
            CheckMessage(message, violations);
        }

        return violations;
    }

    private static void CheckEnum(EnumDescriptorProto enumType, List<string> violations)
    {
        string unspecified = $"{UpperSnake(enumType.Name)}_UNSPECIFIED";
        if (enumType.Value.Count == 0 || enumType.Value[0].Number != 0 || enumType.Value[0].Name != unspecified)
        {
            violations.Add($"S7: enum {enumType.Name} does not start with {unspecified} = 0.");
        }
    }

    private static void CheckMessage(DescriptorProto message, List<string> violations)
    {
        foreach (var nested in message.NestedType)
        {
            if (nested.Options?.MapEntry == true)
            {
                violations.Add($"S2: {message.Name} has a map ({nested.Name}).");
            }
            else
            {
                CheckMessage(nested, violations);
            }
        }

        foreach (var nestedEnum in message.EnumType)
        {
            CheckEnum(nestedEnum, violations);
        }

        int previous = 0;
        foreach (var field in message.Field)
        {
            string name = $"{message.Name}.{field.Name}";

            // S2: types.
            switch (field.Type)
            {
                case FieldType.Uint32 or FieldType.Uint64 or FieldType.Bool or FieldType.String or FieldType.Bytes:
                    break;
                case FieldType.Enum:
                    if (!field.TypeName.StartsWith($".{Package}.", StringComparison.Ordinal))
                    {
                        violations.Add($"S2: {name} has enum type {field.TypeName}, outside the package.");
                    }

                    break;
                case FieldType.Message:
                    if (!field.TypeName.StartsWith($".{Package}.", StringComparison.Ordinal) && field.TypeName != ".google.protobuf.Timestamp")
                    {
                        violations.Add($"S2: {name} has message type {field.TypeName}; only this package's messages and google.protobuf.Timestamp are allowed.");
                    }

                    break;
                default:
                    violations.Add($"S2: {name} has type {field.Type}; only uint32, uint64, bool, enum, string, bytes and messages are allowed.");
                    break;
            }

            // S3: a list is a repeated message (or one bytes field), never a repeated scalar.
            if (field.Label == FieldLabel.Repeated && field.Type != FieldType.Message)
            {
                violations.Add($"S3: {name} is a repeated {field.Type}; a list is a repeated message or one bytes field of fixed-width values.");
            }

            // S4: no `optional` keyword.
            if (field.Proto3Optional)
            {
                violations.Add($"S4: {name} uses the optional keyword.");
            }

            // S5: declared in ascending field-number order.
            if (field.Number <= previous)
            {
                violations.Add($"S5: {name} ({field.Number}) is declared after field {previous}.");
            }

            previous = Math.Max(previous, field.Number);

            // S6: reserved numbers are never reused; hot messages keep one-byte tags.
            if (message.ReservedRange.Any(r => field.Number >= r.Start && field.Number < r.End) || message.ReservedName.Contains(field.Name))
            {
                violations.Add($"S6: {name} uses reserved number {field.Number} or a reserved name.");
            }

            if (HotMessages.Contains(message.Name) && field.Number > 15)
            {
                violations.Add($"S6: {name} is numbered {field.Number}; fields of {message.Name} stay at 15 or below (one-byte tags).");
            }

            // S7: width options.
            var options = field.Options;
            bool hasWidth = options?.HasExtension(EgrfExtensions.Width) == true;
            bool hasMultiple = options?.HasExtension(EgrfExtensions.WidthMultiple) == true;
            bool omittable = options?.HasExtension(EgrfExtensions.Omittable) == true;
            if ((hasWidth || hasMultiple || omittable) && (field.Type != FieldType.Bytes || field.Label == FieldLabel.Repeated))
            {
                violations.Add($"S7: {name} has a width option but is not a singular bytes field.");
            }
            else if (hasWidth && hasMultiple)
            {
                violations.Add($"S7: {name} has both width and width_multiple.");
            }
            else if (omittable && !(hasWidth || hasMultiple))
            {
                violations.Add($"S7: {name} is omittable but has no width option.");
            }
            else if ((hasWidth && options!.GetExtension(EgrfExtensions.Width) == 0) || (hasMultiple && options!.GetExtension(EgrfExtensions.WidthMultiple) == 0))
            {
                violations.Add($"S7: {name} has a width of 0.");
            }
            else if (field.Type == FieldType.Bytes && !hasWidth && !hasMultiple && !VariableLengthBytes.Contains(name))
            {
                violations.Add($"S7: {name} is a bytes field with no width option and is not a listed variable-length field.");
            }
        }

        // S8: a oneof's members are messages. A set member is written even when its value is the
        // default (W2), so a scalar member would put an explicit 0 on the wire, which W6 tells an
        // older reader can never happen in an unknown field.
        foreach (var field in message.Field.Where(f => f.HasOneofIndex && !f.Proto3Optional && f.Type != FieldType.Message))
        {
            violations.Add($"S8: {message.Name}.{field.Name} ({field.Number}) is a member of oneof {message.OneofDecl[field.OneofIndex].Name} with type {field.Type}; oneof members are messages.");
        }

        // S8: no regular field numbered between a oneof's lowest and highest members.
        for (int oneof = 0; oneof < message.OneofDecl.Count; oneof++)
        {
            var members = message.Field.Where(f => f.HasOneofIndex && f.OneofIndex == oneof && !f.Proto3Optional).Select(f => f.Number).ToList();
            if (members.Count == 0)
            {
                continue;
            }

            int low = members.Min(), high = members.Max();
            foreach (var field in message.Field.Where(f => !f.HasOneofIndex && f.Number > low && f.Number < high))
            {
                violations.Add($"S8: {message.Name}.{field.Name} ({field.Number}) lies inside oneof {message.OneofDecl[oneof].Name}'s member range {low}-{high}.");
            }
        }

        // The envelope (design §4.3 D5): a RecordItem's one field is its item member.
        if (message.Name == "RecordItem" && message.Field.Any(f => !f.HasOneofIndex))
        {
            violations.Add("S8: RecordItem has a regular field; its only fields are the members of its item oneof.");
        }
    }

    private static string UpperSnake(string name) =>
        string.Concat(name.Select((c, i) => i > 0 && char.IsUpper(c) ? $"_{c}" : char.ToUpperInvariant(c).ToString()));

    // ---- the schema table (test/egrf/schema.json) and the append-only rule ----------------------

    /// <summary>
    /// The schema as a table: per message, its reserved numbers and its fields (number, name, type,
    /// label, type name, oneof, width options); per enum, its values. Messages and enums in
    /// declaration order. A reader in another language transcribes this; the append-only check
    /// compares two of these.
    /// </summary>
    public static JsonObject Table(FileDescriptorProto file)
    {
        var messages = new JsonArray();
        foreach (var message in file.MessageType)
        {
            var fields = new JsonArray();
            foreach (var field in message.Field)
            {
                var entry = new JsonObject
                {
                    ["number"] = field.Number,
                    ["name"] = field.Name,
                    ["type"] = field.Type.ToString().ToLowerInvariant(),
                    ["label"] = field.Label.ToString().ToLowerInvariant(),
                };
                if (field.Type is FieldType.Message or FieldType.Enum)
                {
                    entry["typeName"] = field.TypeName;
                }

                if (field.HasOneofIndex)
                {
                    entry["oneof"] = message.OneofDecl[field.OneofIndex].Name;
                }

                if (field.Options?.HasExtension(EgrfExtensions.Width) == true)
                {
                    entry["width"] = field.Options.GetExtension(EgrfExtensions.Width);
                }

                if (field.Options?.HasExtension(EgrfExtensions.WidthMultiple) == true)
                {
                    entry["widthMultiple"] = field.Options.GetExtension(EgrfExtensions.WidthMultiple);
                }

                if (field.Options?.HasExtension(EgrfExtensions.Omittable) == true)
                {
                    entry["omittable"] = field.Options.GetExtension(EgrfExtensions.Omittable);
                }

                fields.Add(entry);
            }

            var reserved = new JsonArray();
            foreach (var range in message.ReservedRange)
            {
                for (int number = range.Start; number < range.End; number++)
                {
                    reserved.Add(number);
                }
            }

            messages.Add(new JsonObject { ["name"] = message.Name, ["reserved"] = reserved, ["fields"] = fields });
        }

        var enums = new JsonArray();
        foreach (var enumType in file.EnumType)
        {
            var values = new JsonArray();
            foreach (var value in enumType.Value)
            {
                values.Add(new JsonObject { ["number"] = value.Number, ["name"] = value.Name });
            }

            enums.Add(new JsonObject { ["name"] = enumType.Name, ["values"] = values });
        }

        return new JsonObject
        {
            ["package"] = file.Package,
            ["note"] = "Generated from proto/electionguard/egrf/v2/egrf.proto by EgrfSchemaLintTests; do not edit by hand.",
            ["messages"] = messages,
            ["enums"] = enums,
        };
    }

    public static string TableText(JsonObject table) => table.ToJsonString(new JsonSerializerOptions { WriteIndented = true }).Replace("\r\n", "\n") + "\n";

    /// <summary>
    /// The append-only rule (S6) between a published table and a newer one: no message, enum,
    /// field, enum value or reserved number disappears; a field keeps its number, name, type,
    /// label, type name, oneof and width options, unless its number became reserved; a new field
    /// is numbered above every number its message declared or reserved before (so it follows every
    /// known field on the wire), except a new member of RecordItem's item oneof, which may take any
    /// number not used or reserved before (a new item type, §7).
    /// </summary>
    public static List<string> AppendOnlyViolations(JsonObject published, JsonObject current)
    {
        var violations = new List<string>();
        var currentMessages = current["messages"]!.AsArray().ToDictionary(m => (string)m!["name"]!, m => m!.AsObject());
        foreach (var oldMessage in published["messages"]!.AsArray().Select(m => m!.AsObject()))
        {
            string name = (string)oldMessage["name"]!;
            if (!currentMessages.TryGetValue(name, out var newMessage))
            {
                violations.Add($"S6: message {name} was removed.");
                continue;
            }

            var oldReserved = oldMessage["reserved"]!.AsArray().Select(n => (int)n!).ToHashSet();
            var newReserved = newMessage["reserved"]!.AsArray().Select(n => (int)n!).ToHashSet();
            foreach (int number in oldReserved.Except(newReserved))
            {
                violations.Add($"S6: {name} no longer reserves {number}.");
            }

            var oldFields = oldMessage["fields"]!.AsArray().ToDictionary(f => (int)f!["number"]!, f => f!.AsObject());
            var newFields = newMessage["fields"]!.AsArray().ToDictionary(f => (int)f!["number"]!, f => f!.AsObject());
            foreach (var (number, oldField) in oldFields)
            {
                if (!newFields.TryGetValue(number, out var newField))
                {
                    if (!newReserved.Contains(number))
                    {
                        violations.Add($"S6: {name}.{oldField["name"]} ({number}) was removed without reserving its number.");
                    }
                }
                else if (!JsonNode.DeepEquals(oldField, newField))
                {
                    violations.Add($"S6: {name} field {number} changed from {oldField.ToJsonString()} to {newField.ToJsonString()}.");
                }
            }

            int highest = oldFields.Keys.Concat(oldReserved).DefaultIfEmpty(0).Max();
            foreach (var (number, newField) in newFields.Where(f => !oldFields.ContainsKey(f.Key)))
            {
                bool newItemType = name == "RecordItem" && (string?)newField["oneof"] == "item" && !oldReserved.Contains(number);
                if (number <= highest && !newItemType)
                {
                    violations.Add($"S6: {name}.{newField["name"]} is numbered {number}, not above {highest}, the highest number {name} declared or reserved before.");
                }
            }
        }

        var currentEnums = current["enums"]!.AsArray().ToDictionary(e => (string)e!["name"]!, e => e!.AsObject());
        foreach (var oldEnum in published["enums"]!.AsArray().Select(e => e!.AsObject()))
        {
            string name = (string)oldEnum["name"]!;
            if (!currentEnums.TryGetValue(name, out var newEnum))
            {
                violations.Add($"S6: enum {name} was removed.");
                continue;
            }

            var newValues = newEnum["values"]!.AsArray().Select(v => v!.ToJsonString()).ToHashSet();
            foreach (var value in oldEnum["values"]!.AsArray().Where(v => !newValues.Contains(v!.ToJsonString())))
            {
                violations.Add($"S6: enum {name} value {value!.ToJsonString()} was removed or renumbered.");
            }
        }

        return violations;
    }
}
