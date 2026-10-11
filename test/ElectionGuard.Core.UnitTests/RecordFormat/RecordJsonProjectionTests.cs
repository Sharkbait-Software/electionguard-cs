using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.Verify;
using Google.Protobuf;
using System.Text;
using static ElectionGuard.Core.UnitTests.RecordFormat.RecordCarrierElections;
using static ElectionGuard.Core.UnitTests.RecordFormat.RecordDirectoryCarrierTests;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// S10b-10: the JSON projection (design §5.5), the converter and the diff. Every golden item and the
/// whole test election go protobuf → JSON → protobuf byte for byte; the four representations
/// (directory or zip, protobuf or JSON) of one election have the same roots and no difference; the
/// reader refuses an ambiguous or unknown JSON member, and the canonicality check refuses what the
/// mapping lets through (widths, integer bounds, timestamps); content of a newer minor is copied
/// protobuf to protobuf unchanged and refused for JSON.
/// </summary>
public class RecordJsonProjectionTests
{
    public RecordJsonProjectionTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    [Fact]
    public void GoldenItems_GoProtobufToJsonToProtobuf_ByteForByte_InCompactLines()
    {
        foreach (var (name, item) in EgrfVectors.GoldenItems())
        {
            byte[] bytes = item.ToByteArray();
            byte[] line = RecordJson.FormatItem(bytes, CanonicalProtobuf.Check(bytes, 0));
            string text = Encoding.UTF8.GetString(line);
            Assert.DoesNotContain('\n', text);
            Assert.DoesNotContain("\": ", text);
            Assert.DoesNotContain("\\u002B", text);
            Assert.Equal(bytes, RecordJson.ParseItem(line, 0));
            Assert.True(CanonicalProtobuf.Check(RecordJson.ParseItem(line, 0), 0).IsCanonical, name);
        }

        var header = EgrfVectors.GoldenSegmentHeader();
        Assert.Equal(header.ToByteArray(), RecordJson.ParseSegmentHeader(RecordJson.FormatSegmentHeader(header), 0));
    }

    [Fact]
    public async Task FullElection_ProtobufToJsonToProtobuf_IsByteIdentical_AndAllFourRepresentationsHaveTheSameRoots()
    {
        string protobuf = TempDirectory("four-pb");
        var tocs = await WriteAsync(RegularElection.Value, protobuf, RecordEncoding.Protobuf);
        string json = Path.Combine(TempDirectory("four"), "json");
        string back = Path.Combine(TempDirectory("four"), "back");
        string protobufZip = Path.Combine(TempDirectory("four"), "pb.zip");
        string jsonZip = Path.Combine(TempDirectory("four"), "json.zip");
        string written = TempDirectory("four-written-json");
        await WriteAsync(RegularElection.Value, written, RecordEncoding.Json);

        await using (var source = await ElectionRecord.OpenAsync(protobuf))
        {
            await ElectionRecord.ConvertAsync(source, json, RecordEncoding.Json, RecordCarrier.Directory);
            await ElectionRecord.ConvertAsync(source, protobufZip, RecordEncoding.Protobuf, RecordCarrier.Zip);
        }

        await using (var source = await ElectionRecord.OpenAsync(json))
        {
            await ElectionRecord.ConvertAsync(source, back, RecordEncoding.Protobuf, RecordCarrier.Directory);
            await ElectionRecord.ConvertAsync(source, jsonZip, RecordEncoding.Json, RecordCarrier.Zip);
        }

        // protobuf → JSON → protobuf: every file of the record byte for byte.
        var files = System.IO.Directory.EnumerateFiles(protobuf, "*", SearchOption.AllDirectories).Select(x => Path.GetRelativePath(protobuf, x)).Order(StringComparer.Ordinal).ToList();
        Assert.Equal(files, System.IO.Directory.EnumerateFiles(back, "*", SearchOption.AllDirectories).Select(x => Path.GetRelativePath(back, x)).Order(StringComparer.Ordinal));
        foreach (var file in files)
        {
            Assert.True(File.ReadAllBytes(Path.Combine(protobuf, file)).AsSpan().SequenceEqual(File.ReadAllBytes(Path.Combine(back, file))), file);
        }

        // The JSON the converter wrote is the JSON the writer writes.
        foreach (var file in System.IO.Directory.EnumerateFiles(written, "*.jsonl", SearchOption.AllDirectories))
        {
            Assert.Equal(File.ReadAllBytes(file), File.ReadAllBytes(Path.Combine(json, Path.GetRelativePath(written, file))));
        }

        var readers = new List<IElectionRecordReader>();
        try
        {
            foreach (var path in new[] { protobuf, json, protobufZip, jsonZip, written, back })
            {
                readers.Add(await ElectionRecord.OpenAsync(path));
            }

            foreach (var reader in readers)
            {
                var toc = await ElectionRecord.CheckClaimedTocAsync(reader);
                Assert.Equal(tocs[RecordPhase.Final].Entries, toc.Entries);
                foreach (var phase in Enum.GetValues<RecordPhase>())
                {
                    Assert.Equal(tocs[phase].Root, toc.PhaseRoot(phase));
                }

                Assert.Empty(await ElectionRecord.DiffAsync(readers[0], reader).ToListAsync());
            }

            await ReadAsync(readers[3]);
        }
        finally
        {
            foreach (var reader in readers)
            {
                await reader.DisposeAsync();
            }
        }
    }

    public static TheoryData<string, string, string> JsonNegatives() => new()
    {
        { "a member named twice", "{\"recordHeader\":{\"formatMajor\":2,\"formatMajor\":2}}", RecordCodes.Encoding },
        { "a JSON-name and proto-name alias pair", "{\"recordHeader\":{\"formatMajor\":2,\"format_major\":3}}", RecordCodes.Encoding },
        { "two members of one oneof", "{\"recordHeader\":{\"formatMajor\":2},\"parameters\":{}}", RecordCodes.Encoding },
        { "an unknown member", "{\"recordHeader\":{\"formatMajor\":2,\"formatPatch\":1}}", RecordCodes.Encoding },
        { "an unknown item type", "{\"recordHeaderV3\":{}}", RecordCodes.Encoding },
        { "an undeclared enum name", "{\"deviceHeader\":{\"kind\":\"DEVICE_KIND_TABLET\",\"deviceId\":\"d\",\"hDi\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}}", RecordCodes.Encoding },
        { "not JSON", "{\"recordHeader\":", RecordCodes.Encoding },
        { "a byte order mark", "\uFEFF{\"recordHeader\":{\"formatMajor\":2}}", RecordCodes.Encoding },
        { "a lone surrogate escape", "{\"deviceHeader\":{\"deviceId\":\"\\uD800\"}}", RecordCodes.Encoding },
    };

    [Theory]
    [MemberData(nameof(JsonNegatives))]
    public void JsonLine_ThatIsNotOneUnambiguousItem_IsRefused(string row, string line, string code)
    {
        var failure = Assert.Throws<VerificationFailedException>(() => RecordJson.ParseItem(Encoding.UTF8.GetBytes(line), 0));
        Assert.True(code == failure.SubSection, $"{row}: {failure.SubSection} {failure.Message}");
    }

    /// <summary>
    /// An unknown member, or an enum value name this library does not declare, in a record of a
    /// newer minor cannot be carried to canonical bytes without its number: R.version (§7, "Enum
    /// value" and "Older readers"). At this library's minor the same lines are R.encoding (above).
    /// </summary>
    [Theory]
    [InlineData("an unknown member", "{\"recordHeader\":{\"formatMajor\":2,\"formatPatch\":1}}")]
    [InlineData("an undeclared enum name", "{\"recordStatement\":{\"phase\":\"RECORD_PHASE_AUDITED\"}}")]
    [InlineData("an undeclared enum name in a nested message", "{\"encryptedBallot\":{\"status\":\"BALLOT_STATUS_PROVISIONAL\"}}")]
    public void UnknownJsonContent_InANewerMinorRecord_IsRVersion(string row, string line)
    {
        var failure = Assert.Throws<VerificationFailedException>(() => RecordJson.ParseItem(Encoding.UTF8.GetBytes(line), 1));
        Assert.True(RecordCodes.Version == failure.SubSection, $"{row}: {failure.SubSection} {failure.Message}");
        var current = Assert.Throws<VerificationFailedException>(() => RecordJson.ParseItem(Encoding.UTF8.GetBytes(line), 0));
        Assert.True(RecordCodes.Encoding == current.SubSection, $"{row} at this minor: {current.SubSection} {current.Message}");
    }

    /// <summary>
    /// <c>DeviceKind</c> and <c>SectionType</c> are closed (user decisions NQ-9 and NQ-7): no minor
    /// adds a value, so an undeclared name of either is R.encoding in a record of any minor, never
    /// R.version (a newer record cannot have it).
    /// </summary>
    [Theory]
    [InlineData("a device kind in a header", "{\"deviceHeader\":{\"kind\":\"DEVICE_KIND_TABLET\",\"deviceId\":\"d\",\"hDi\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}}")]
    [InlineData("a device kind in a ballot locator", "{\"challengedBallotDecryption\":{\"ballot\":{\"kind\":\"DEVICE_KIND_TABLET\"}}}")]
    [InlineData("a section type in a TOC entry", "{\"tocEntry\":{\"sectionType\":\"SECTION_TYPE_VENDOR\"}}")]
    public void UndeclaredNameOfAClosedEnum_IsREncoding_AtAnyMinor(string row, string line)
    {
        foreach (ushort minor in new ushort[] { 0, 1 })
        {
            var failure = Assert.Throws<VerificationFailedException>(() => RecordJson.ParseItem(Encoding.UTF8.GetBytes(line), minor));
            Assert.True(RecordCodes.Encoding == failure.SubSection, $"{row} at minor {minor}: {failure.SubSection} {failure.Message}");
        }
    }

    public static TheoryData<string, string, string> DecodeRuleNegatives() => new()
    {
        { "an id_B of 31 bytes", "{\"encryptedBallot\":{\"idB\":\"" + Convert.ToBase64String(new byte[31]) + "\"}}", "D1" },
        { "a uint64 of 2^63", "{\"deviceClose\":{\"ballotCount\":\"9223372036854775808\"}}", "D4" },
        { "a timestamp before 1970", "{\"deviceClose\":{\"ballotCount\":\"1\",\"closedAt\":\"1969-12-31T23:59:59.999Z\"}}", "D3" },
        { "a timestamp with microseconds", "{\"deviceClose\":{\"ballotCount\":\"1\",\"closedAt\":\"2026-11-03T20:00:00.000001Z\"}}", "D3" },
        { "an empty item", "{}", "D5" },
        { "a status UNSPECIFIED", "{\"challengedBallotDecryption\":{\"ballot\":{\"kind\":\"DEVICE_KIND_UNSPECIFIED\"}}}", "D2" },
    };

    /// <summary>
    /// What the proto3 JSON mapping accepts but the profile does not is caught on the canonical
    /// encoding of the parsed line (design §5.5: D1-D6 apply to JSON too).
    /// </summary>
    [Theory]
    [MemberData(nameof(DecodeRuleNegatives))]
    public void JsonLine_ThatParses_IsStillCheckedByTheDecodeRules(string row, string line, string rule)
    {
        byte[] bytes = RecordJson.ParseItem(Encoding.UTF8.GetBytes(line), 0);
        var check = CanonicalProtobuf.Check(bytes, 0);
        Assert.False(check.IsCanonical, row);
        Assert.True(rule == check.Rule, $"{row}: {check.Rule} {check.Message}");
    }

    /// <summary>
    /// A record of a newer minor whose ballot carries an unknown field (W6: after every known field,
    /// numbered above them): protobuf to protobuf copies it byte for byte, so the roots survive; to
    /// JSON it is refused (R.version) rather than dropped (design §5.1).
    /// </summary>
    [Fact]
    public async Task NewerMinorContent_IsCopiedProtobufToProtobuf_AndRefusedForJson()
    {
        string directory = TempDirectory("newer-minor");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf);
        string headerPath = Path.Combine(directory, "setup", "header.binpb");
        var headerFrames = Frames(File.ReadAllBytes(headerPath));
        headerFrames[1] = Frame(new Pb.RecordItem { RecordHeader = new Pb.RecordHeader { FormatMajor = 2, FormatMinor = 1 } }.ToByteArray());
        File.WriteAllBytes(headerPath, Join(headerFrames));
        string device1 = DeviceOne(directory);
        string segment = Path.Combine(device1, "00000000.binpb");
        var frames = Frames(File.ReadAllBytes(segment));
        var ballot = Pb.RecordItem.Parser.ParseFrom(Payload(frames[2])).EncryptedBallot;
        byte[] inner = [.. ballot.ToByteArray(), 0xA0, 0x01, 0x01]; // field 20, VARINT 1
        frames[2] = Frame([0x5A, .. EgrfVectors.Varint((ulong)inner.Length), .. inner]);
        File.WriteAllBytes(segment, Join(frames));
        File.Delete(Path.Combine(directory, "toc.binpb"));

        await using var source = await ElectionRecord.OpenAsync(directory);
        Assert.Equal(new RecordFormatVersion(2, 1), source.Format);
        var toc = await ElectionRecord.ComputeTocAsync(source);
        bool unknown = false;
        var section = new SectionKey(RecordSectionType.Device, [1, .. Convert.FromHexString(Path.GetFileName(device1)["regular-".Length..])]);
        await foreach (var item in source.ReadSectionAsync(section))
        {
            Assert.True(item.Check.IsCanonical, item.Check.Message);
            unknown |= item.Check.HasUnknownContent;
        }

        Assert.True(unknown);

        string copy = Path.Combine(TempDirectory("newer-minor-copy"), "pb");
        var copied = await ElectionRecord.ConvertAsync(source, copy, RecordEncoding.Protobuf, RecordCarrier.Directory);
        Assert.Equal(toc.Root, copied.Root);
        Assert.Equal(File.ReadAllBytes(segment), File.ReadAllBytes(Path.Combine(copy, Path.GetRelativePath(directory, segment))));

        string json = Path.Combine(TempDirectory("newer-minor-json"), "json");
        var failure = await Assert.ThrowsAsync<VerificationFailedException>(() => ElectionRecord.ConvertAsync(source, json, RecordEncoding.Json, RecordCarrier.Directory).AsTask());
        Assert.Equal(RecordCodes.Version, failure.SubSection);
        Assert.False(System.IO.Directory.Exists(json));
    }

    /// <summary>A JSON record whose line names a member twice is refused by the reader, as R.encoding, at that line.</summary>
    [Fact]
    public async Task JsonRecord_WithADuplicateMember_IsRefusedByTheReader()
    {
        string directory = TempDirectory("json-duplicate");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Json);
        string path = Path.Combine(directory, "setup", "parameters.jsonl");
        var lines = File.ReadAllLines(path);
        lines[1] = lines[1].Replace("{\"parameters\":{", "{\"parameters\":{\"n\":3,", StringComparison.Ordinal);
        File.WriteAllText(path, string.Join('\n', lines) + "\n");

        await using var reader = await ElectionRecord.OpenAsync(directory);
        var failure = await Assert.ThrowsAsync<VerificationFailedException>(() => reader.ReadSetupAsync().AsTask());
        Assert.Equal(RecordCodes.Encoding, failure.SubSection);
        Assert.Contains("more than once", failure.Message);
    }
}
