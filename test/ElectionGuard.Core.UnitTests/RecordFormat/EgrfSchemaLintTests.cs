using ElectionGuard.Core.RecordFormat.Protobuf;
using Google.Protobuf;
using Google.Protobuf.Reflection;
using System.Text.Json.Nodes;
using FieldType = Google.Protobuf.Reflection.FieldDescriptorProto.Types.Type;
using FieldLabel = Google.Protobuf.Reflection.FieldDescriptorProto.Types.Label;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// S10b-2: the normative EGRF v2 schema (proto/electionguard/egrf/v2/egrf.proto) obeys the profile's
/// schema rules S1-S8 (design document §4.2.1), the lint catches each kind of break on a broken
/// copy, and test/egrf/schema.json pins the schema so that every change to it is append-only (S6).
/// </summary>
public class EgrfSchemaLintTests
{
    [Fact]
    public void Schema_ObeysTheProfile()
    {
        Assert.Empty(EgrfSchemaLint.Violations(EgrfSchemaLint.Compiled()));
    }

    [Fact]
    public void Schema_HasNoExtensionListAndNoElectionInfo_AndTheCompactUncastItem()
    {
        // User decisions NQ-1 (no per-item extensions), NQ-4 (the header carries only the format
        // version) and NQ-2 (the compact form of an uncast pre-encrypted ballot).
        var file = EgrfSchemaLint.Compiled();
        var recordItem = file.MessageType.Single(m => m.Name == "RecordItem");
        Assert.All(recordItem.Field, f => Assert.True(f.HasOneofIndex));
        Assert.Contains(recordItem.ReservedRange, r => r.Start == 2047);
        Assert.Contains(recordItem.Field, f => f.Name == "pre_encrypted_compact_uncast_ballot" && f.Number == 16);
        Assert.DoesNotContain(file.MessageType, m => m.Name is "Extension" or "ElectionInfo");
        var header = file.MessageType.Single(m => m.Name == "RecordHeader");
        Assert.Equal(["format_major", "format_minor"], header.Field.Select(f => f.Name));
        Assert.Equal(
            ["id_b", "h_i", "ballot_style", "contests", "confirmation_code", "chaining_field", "encrypted_ballot_nonce", "ballot_ref"],
            file.MessageType.Single(m => m.Name == "PreEncryptedCompactUncastBallot").Field.Select(f => f.Name));
    }

    /// <summary>
    /// The generated types are internal (the public API stays the domain types) and the record's
    /// status numbers match the domain enum's.
    /// </summary>
    [Fact]
    public void GeneratedTypes_AreInternal_AndStatusNumbersMatchTheDomain()
    {
        Assert.False(typeof(RecordItem).IsPublic);
        Assert.False(typeof(EgrfReflection).IsPublic);
        Assert.Equal((int)global::ElectionGuard.Core.BallotEncryption.BallotStatus.Cast, (int)global::ElectionGuard.Core.RecordFormat.Protobuf.BallotStatus.Cast);
        Assert.Equal((int)global::ElectionGuard.Core.BallotEncryption.BallotStatus.Challenged, (int)global::ElectionGuard.Core.RecordFormat.Protobuf.BallotStatus.Challenged);
        Assert.Equal((int)global::ElectionGuard.Core.BallotEncryption.BallotStatus.Spoiled, (int)global::ElectionGuard.Core.RecordFormat.Protobuf.BallotStatus.Spoiled);
        Assert.Equal((int)global::ElectionGuard.Core.BallotEncryption.BallotStatus.Unrecorded, (int)global::ElectionGuard.Core.RecordFormat.Protobuf.BallotStatus.Unspecified);
    }

    // ---- the lint catches each break, on a broken copy of the real schema ------------------------

    private static FieldDescriptorProto Field(string name, int number, FieldType type, FieldLabel label = FieldLabel.Optional, string? typeName = null)
    {
        var field = new FieldDescriptorProto { Name = name, Number = number, Type = type, Label = label, JsonName = name };
        if (typeName is not null)
        {
            field.TypeName = typeName;
        }

        return field;
    }

    /// <summary>
    /// Each break, the rule that must catch it and a fragment of the violation's text. Each broken
    /// copy breaks exactly one check, and the test asserts that nothing else fires, so a check that
    /// stopped working cannot hide behind another one that reports the same rule.
    /// </summary>
    public static TheoryData<string, string, string> Breaks() => new()
    {
        { "a map field", "S2", "has a map" },
        { "an int32 field", "S2", "has type Int32" },
        { "a double field", "S2", "has type Double" },
        { "a sint64 field", "S2", "has type Sint64" },
        { "a message from another package", "S2", "has message type .google.protobuf.Any" },
        { "a repeated uint32 field", "S3", "is a repeated Uint32" },
        { "a repeated string field", "S3", "is a repeated String" },
        { "an optional keyword", "S4", "uses the optional keyword" },
        { "fields declared out of number order", "S5", "is declared after field" },
        { "a field using a reserved number", "S6", "uses reserved number 3" },
        { "a hot message field above 15", "S6", "stay at 15 or below" },
        { "a fixed-width bytes field without a width", "S7", "is not a listed variable-length field" },
        { "a width on a string field", "S7", "is not a singular bytes field" },
        { "omittable without a width", "S7", "is omittable but has no width option" },
        { "an enum without UNSPECIFIED = 0", "S7", "does not start with DEVICE_KIND_UNSPECIFIED = 0" },
        { "a regular field inside a oneof's member range", "S8", "DeviceClose.flags (6) lies inside oneof choice's member range 5-7" },
        { "a scalar oneof member", "S8", "DeviceClose.count (5) is a member of oneof choice with type Uint32" },
        { "a regular field in RecordItem", "S8", "RecordItem has a regular field" },
        { "proto2 syntax", "S1", "is \"proto2\", not proto3" },
    };

    [Theory]
    [MemberData(nameof(Breaks))]
    public void Lint_CatchesEachBreak(string description, string rule, string text)
    {
        var file = EgrfSchemaLint.Compiled();
        DescriptorProto Message(string name) => file.MessageType.Single(m => m.Name == name);

        switch (description)
        {
            case "a map field":
                var entry = new DescriptorProto { Name = "LabelsEntry", Options = new MessageOptions { MapEntry = true } };
                entry.Field.Add(Field("key", 1, FieldType.String));
                entry.Field.Add(Field("value", 2, FieldType.String));
                Message("DeviceClose").NestedType.Add(entry);
                Message("DeviceClose").Field.Add(Field("labels", 5, FieldType.Message, FieldLabel.Repeated, ".electionguard.egrf.v2.DeviceClose.LabelsEntry"));
                break;
            case "an int32 field":
                Message("DeviceClose").Field.Add(Field("offset", 5, FieldType.Int32));
                break;
            case "a double field":
                Message("DeviceClose").Field.Add(Field("ratio", 5, FieldType.Double));
                break;
            case "a sint64 field":
                Message("DeviceClose").Field.Add(Field("delta", 5, FieldType.Sint64));
                break;
            case "a message from another package":
                Message("DeviceClose").Field.Add(Field("any", 5, FieldType.Message, typeName: ".google.protobuf.Any"));
                break;
            case "a repeated uint32 field":
                Message("DeviceClose").Field.Add(Field("counts", 5, FieldType.Uint32, FieldLabel.Repeated));
                break;
            case "a repeated string field":
                Message("DeviceClose").Field.Add(Field("notes", 5, FieldType.String, FieldLabel.Repeated));
                break;
            case "an optional keyword":
                var optional = Field("note", 5, FieldType.String);
                optional.Proto3Optional = true;
                optional.OneofIndex = 0;
                Message("DeviceClose").OneofDecl.Add(new OneofDescriptorProto { Name = "_note" });
                Message("DeviceClose").Field.Add(optional);
                break;
            case "fields declared out of number order":
                var fields = Message("DeviceClose").Field;
                var first = fields[0];
                fields.RemoveAt(0);
                fields.Add(first);
                break;
            case "a field using a reserved number":
                Message("RecordHeader").Field.Add(Field("election_info", 3, FieldType.String));
                break;
            case "a hot message field above 15":
                Message("EncryptedField").Field.Add(Field("extra", 16, FieldType.Uint32));
                break;
            case "a fixed-width bytes field without a width":
                Message("DeviceClose").Field.Add(Field("digest", 5, FieldType.Bytes));
                break;
            case "a width on a string field":
                var labelled = Field("label", 5, FieldType.String);
                labelled.Options = new FieldOptions();
                labelled.Options.SetExtension(EgrfExtensions.Width, 32u);
                Message("DeviceClose").Field.Add(labelled);
                break;
            case "omittable without a width":
                var omittable = Field("token", 5, FieldType.Bytes);
                omittable.Options = new FieldOptions();
                omittable.Options.SetExtension(EgrfExtensions.Omittable, true);
                Message("DeviceClose").Field.Add(omittable);
                break;
            case "an enum without UNSPECIFIED = 0":
                file.EnumType.Single(e => e.Name == "DeviceKind").Value[0].Name = "DEVICE_KIND_NONE";
                break;
            case "a regular field inside a oneof's member range":
                // Not in RecordItem, whose own rule would fire too: a oneof in another message, with
                // message members 5 and 7 (S8's member rule holds) and a regular field 6 between.
                Message("DeviceClose").OneofDecl.Add(new OneofDescriptorProto { Name = "choice" });
                var low = Field("low_member", 5, FieldType.Message, typeName: ".electionguard.egrf.v2.ConfirmationCodeLeaf");
                low.OneofIndex = 0;
                var high = Field("high_member", 7, FieldType.Message, typeName: ".electionguard.egrf.v2.ConfirmationCodeLeaf");
                high.OneofIndex = 0;
                Message("DeviceClose").Field.Add(low);
                Message("DeviceClose").Field.Add(Field("flags", 6, FieldType.Uint32));
                Message("DeviceClose").Field.Add(high);
                break;
            case "a scalar oneof member":
                Message("DeviceClose").OneofDecl.Add(new OneofDescriptorProto { Name = "choice" });
                var scalar = Field("count", 5, FieldType.Uint32);
                scalar.OneofIndex = 0;
                var member = Field("member", 6, FieldType.Message, typeName: ".electionguard.egrf.v2.ConfirmationCodeLeaf");
                member.OneofIndex = 0;
                Message("DeviceClose").Field.Add(scalar);
                Message("DeviceClose").Field.Add(member);
                break;
            case "a regular field in RecordItem":
                // Above every member and reservation, so the member-range rule does not fire.
                Message("RecordItem").Field.Add(Field("flags", 3000, FieldType.Uint32));
                break;
            case "proto2 syntax":
                file.Syntax = "proto2";
                break;
            default:
                throw new ArgumentException(description);
        }

        var violation = Assert.Single(EgrfSchemaLint.Violations(file));

        Assert.StartsWith($"{rule}:", violation, StringComparison.Ordinal);
        Assert.Contains(text, violation, StringComparison.Ordinal);
    }

    // ---- test/egrf/schema.json: the table, and the append-only rule -----------------------------

    private static string SchemaJsonPath()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "electionguard-cs.sln")))
        {
            directory = directory.Parent;
        }

        return Path.Combine(directory!.FullName, "test", "egrf", "schema.json");
    }

    /// <summary>
    /// test/egrf/schema.json is the schema as a table, generated from the compiled descriptor. A
    /// schema change must be append-only against the committed table (S6); to accept one, run this
    /// test with EGRF_WRITE_SCHEMA=1, which checks the change and then rewrites the file.
    /// </summary>
    [Fact]
    public void SchemaJson_MatchesTheSchema_AndEveryChangeIsAppendOnly()
    {
        string path = SchemaJsonPath();
        var current = EgrfSchemaLint.Table(EgrfSchemaLint.Compiled());
        string currentText = EgrfSchemaLint.TableText(current);

        Assert.True(File.Exists(path) || Environment.GetEnvironmentVariable("EGRF_WRITE_SCHEMA") == "1", $"{path} is missing; run with EGRF_WRITE_SCHEMA=1 to create it.");
        if (File.Exists(path))
        {
            var published = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
            Assert.Empty(EgrfSchemaLint.AppendOnlyViolations(published, current));
        }

        if (Environment.GetEnvironmentVariable("EGRF_WRITE_SCHEMA") == "1")
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, currentText);
        }

        Assert.Equal(currentText, File.ReadAllText(path).Replace("\r\n", "\n"));
    }

    /// <summary>
    /// Each break and a fragment of the one violation it must produce. Every break is isolated:
    /// adding a field below the highest number, or at a reserved number, leaves every reservation in
    /// place, so only the numbering check (the basis of W6: an unknown field follows every known
    /// one) can catch it.
    /// </summary>
    public static TheoryData<string, string> AppendOnlyBreaks() => new()
    {
        { "a field removed without reserving its number", "DeviceClose.closed_at (4) was removed without reserving its number" },
        { "a field renumbered", "DeviceClose.closed_at (4) was removed without reserving its number" },
        { "a field's type changed", "DeviceClose field 1 changed from" },
        { "a field's width changed", "ElectionKeys field 3 changed from" },
        { "a field added below the highest number", "DeviceClose.note is numbered 5, not above 6" },
        { "a field added at a reserved number", "RecordHeader.election_info is numbered 3, not above 3" },
        { "an item type added at a reserved number", "RecordItem.extensions is numbered 2047, not above 2047" },
        { "a reservation dropped", "RecordItem no longer reserves 2047" },
        { "an enum value removed", "enum BallotStatus value" },
        { "a message removed", "message ConfirmationCodeLeaf was removed" },
    };

    [Theory]
    [MemberData(nameof(AppendOnlyBreaks))]
    public void AppendOnly_CatchesEachBreak(string description, string text)
    {
        var published = EgrfSchemaLint.Table(EgrfSchemaLint.Compiled());
        var file = EgrfSchemaLint.Compiled();
        DescriptorProto Message(string name) => file.MessageType.Single(m => m.Name == name);

        switch (description)
        {
            case "a field removed without reserving its number":
                Message("DeviceClose").Field.RemoveAt(3);
                break;
            case "a field renumbered":
                Message("DeviceClose").Field[3].Number = 5;
                break;
            case "a field's type changed":
                Message("DeviceClose").Field[0].Type = FieldType.Uint32;
                break;
            case "a field's width changed":
                Message("ElectionKeys").Field[2].Options.SetExtension(EgrfExtensions.Width, 64u);
                break;
            case "a field added below the highest number":
                // Every number below the highest is in use or reserved in the real schema, so the
                // published table here is one minor later, with DeviceClose field 6 appended; this
                // minor then adds field 5 in the gap, below 6, with no reservation touched.
                var earlier = EgrfSchemaLint.Compiled();
                earlier.MessageType.Single(m => m.Name == "DeviceClose").Field.Add(Field("note", 6, FieldType.String));
                published = EgrfSchemaLint.Table(earlier);
                Message("DeviceClose").Field.Add(Field("note", 5, FieldType.String));
                Message("DeviceClose").Field.Add(Field("note", 6, FieldType.String));
                break;
            case "a field added at a reserved number":
                // The reservation stays, so only the numbering check can catch it.
                Message("RecordHeader").Field.Add(Field("election_info", 3, FieldType.String));
                break;
            case "an item type added at a reserved number":
                // RecordItem's exemption admits a new item type at an unused number, never at a
                // reserved one; the reservation stays.
                var extensions = Field("extensions", 2047, FieldType.Message, typeName: ".electionguard.egrf.v2.ConfirmationCodeLeaf");
                extensions.OneofIndex = 0;
                Message("RecordItem").Field.Add(extensions);
                break;
            case "a reservation dropped":
                var recordItemReserved = Message("RecordItem").ReservedRange;
                recordItemReserved.Remove(recordItemReserved.Single(r => r.Start == 2047));
                break;
            case "an enum value removed":
                file.EnumType.Single(e => e.Name == "BallotStatus").Value.RemoveAt(3);
                break;
            case "a message removed":
                file.MessageType.Remove(Message("ConfirmationCodeLeaf"));
                break;
            default:
                throw new ArgumentException(description);
        }

        var violation = Assert.Single(EgrfSchemaLint.AppendOnlyViolations(published, EgrfSchemaLint.Table(file)));

        Assert.StartsWith("S6:", violation, StringComparison.Ordinal);
        Assert.Contains(text, violation, StringComparison.Ordinal);
    }

    [Fact]
    public void AppendOnly_AcceptsAFieldAppendedAboveEveryNumber_AndANewItemType()
    {
        var published = EgrfSchemaLint.Table(EgrfSchemaLint.Compiled());
        var file = EgrfSchemaLint.Compiled();
        file.MessageType.Single(m => m.Name == "DeviceClose").Field.Add(Field("note", 5, FieldType.String));
        var recordItem = file.MessageType.Single(m => m.Name == "RecordItem");
        var newItem = Field("tally_definition", 23, FieldType.Message, typeName: ".electionguard.egrf.v2.ConfirmationCodeLeaf");
        newItem.OneofIndex = 0;
        recordItem.Field.Insert(recordItem.Field.IndexOf(recordItem.Field.Single(f => f.Number == 30)), newItem);

        Assert.Empty(EgrfSchemaLint.AppendOnlyViolations(published, EgrfSchemaLint.Table(file)));
        Assert.Empty(EgrfSchemaLint.Violations(file));
    }
}
