using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.Verify;
using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using static ElectionGuard.Core.UnitTests.RecordFormat.RecordCarrierElections;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// S10b-7: the <c>.zip</c> carrier (design §5.4). A record converted from a directory to a zip has
/// the directory's roots in either encoding; protobuf entries are STORED and JSON entries DEFLATEd;
/// the reader takes entries in any order and from a stream that cannot seek (spooled, NQ-6); and it
/// refuses, as <c>R.container</c>, a corrupted entry, a duplicate name, a local header that disagrees
/// with the central directory, an encrypted entry or another method, and names that are not the
/// layout's (traversal, backslash, absolute, case-fold collisions).
/// </summary>
public class RecordZipCarrierTests
{
    public RecordZipCarrierTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static readonly Lazy<string> Directory = new(() =>
    {
        string directory = TempDirectory("zip-source");
        WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf).GetAwaiter().GetResult();
        return directory;
    });

    private static async Task<string> Zip(RecordEncoding encoding, bool deflateJson = true)
    {
        string zip = Path.Combine(TempDirectory("zip"), "record.zip");
        await using var source = await ElectionRecord.OpenAsync(Directory.Value);
        await ElectionRecord.ConvertAsync(source, zip, encoding, RecordCarrier.Zip, deflateJson: deflateJson);
        return zip;
    }

    [Theory]
    [InlineData(RecordEncoding.Protobuf)]
    [InlineData(RecordEncoding.Json)]
    public async Task DirectoryAndZip_HoldTheSameRecord(RecordEncoding encoding)
    {
        string zip = await Zip(encoding);
        await using var directory = await ElectionRecord.OpenAsync(Directory.Value);
        await using var archive = await ElectionRecord.OpenAsync(zip);
        Assert.Equal((RecordCarrier.Zip, encoding, RecordPhase.Final), (archive.Carrier, archive.Encoding, archive.Phase));
        var expected = await ElectionRecord.CheckClaimedTocAsync(directory);
        Assert.Equal(expected.Entries, (await ElectionRecord.CheckClaimedTocAsync(archive)).Entries);
        Assert.Empty(await ElectionRecord.DiffAsync(directory, archive).ToListAsync());
        var contents = await ReadAsync(archive);
        Assert.Equal(RegularElection.Value.Record.ManifestFile.Bytes, contents.Setup.ManifestFile.Bytes);

        // The TOC and the setup first (a convenience, §5.4); protobuf STORED, JSON DEFLATEd.
        using var listing = ZipFile.OpenRead(zip);
        var names = listing.Entries.Select(x => x.FullName).ToList();
        string ext = encoding == RecordEncoding.Protobuf ? "binpb" : "jsonl";
        Assert.Equal($"toc.{ext}", names[0]);
        Assert.Equal($"setup/header.{ext}", names[1]);
        foreach (var entry in listing.Entries.Where(x => x.FullName.EndsWith(ext, StringComparison.Ordinal)))
        {
            if (encoding == RecordEncoding.Protobuf)
            {
                Assert.Equal(entry.Length, entry.CompressedLength);
                Assert.Equal(0, LocalMethod(zip, entry.FullName));
            }
            else if (entry.Length > 1000)
            {
                Assert.Equal(8, LocalMethod(zip, entry.FullName));
                Assert.True(entry.CompressedLength < entry.Length, entry.FullName);
            }
        }
    }

    [Fact]
    public async Task AnyEntryOrder_AndANonSeekableStream_ReadTheSameRecord()
    {
        // Entries in reverse order, written by hand with ZipArchive.
        string reversed = Path.Combine(TempDirectory("zip-reversed"), "record.zip");
        using (var archive = ZipFile.Open(reversed, ZipArchiveMode.Create))
        {
            foreach (var file in System.IO.Directory.EnumerateFiles(Directory.Value, "*", SearchOption.AllDirectories).OrderDescending(StringComparer.Ordinal))
            {
                archive.CreateEntryFromFile(file, Path.GetRelativePath(Directory.Value, file).Replace('\\', '/'), CompressionLevel.NoCompression);
            }
        }

        await using var directory = await ElectionRecord.OpenAsync(Directory.Value);
        var expected = await ElectionRecord.ComputeTocAsync(directory);
        await using (var archive = await ElectionRecord.OpenAsync(reversed))
        {
            Assert.Equal(expected.Root, (await ElectionRecord.CheckClaimedTocAsync(archive)).Root);
        }

        // A stream that cannot seek is spooled to a temporary file first (NQ-6), which is then deleted.
        string spool = TempDirectory("spool");
        await using (var piped = await ElectionRecord.OpenAsync(new ForwardOnlyStream(File.OpenRead(reversed)), spool))
        {
            Assert.Single(System.IO.Directory.GetFiles(spool));
            Assert.Equal(expected.Root, (await ElectionRecord.CheckClaimedTocAsync(piped)).Root);
            await ReadAsync(piped);
        }

        Assert.Empty(System.IO.Directory.GetFiles(spool));
    }

    /// <summary>Each corruption and a fragment of the message of the rule that must refuse it (several rules give R.container).</summary>
    public static TheoryData<string, string> Corruptions() => new()
    {
        { "a byte of a STORED entry's data flipped", "is not what the central directory states" },
        { "the local header's CRC changed", "disagrees with the central directory" },
        { "the local header's name changed", "local header names" },
        { "the central directory's method made 12", "only STORED (0) and DEFLATE (8) are allowed" },
        { "the central directory's encryption bit set", "is encrypted" },
        { "the central directory's size changed", "has a compressed size" },
    };

    [Theory]
    [MemberData(nameof(Corruptions))]
    public async Task CorruptedArchive_IsRefusedAsRContainer(string corruption, string message)
    {
        string zip = await Zip(RecordEncoding.Protobuf);
        byte[] bytes = File.ReadAllBytes(zip);
        var (central, local, data) = Locate(bytes, "setup/parameters.binpb");
        switch (corruption)
        {
            case "a byte of a STORED entry's data flipped": bytes[data + 100] ^= 0x01; break;
            case "the local header's CRC changed": bytes[local + 14] ^= 0x01; break;
            case "the local header's name changed": bytes[local + 30] = (byte)'S'; break;
            case "the central directory's method made 12": BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(central + 10), 12); break;
            case "the central directory's encryption bit set": bytes[central + 8] |= 0x01; break;
            case "the central directory's size changed": BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(central + 24), BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(central + 24)) + 1); break;
        }

        File.WriteAllBytes(zip, bytes);
        var failure = await Assert.ThrowsAsync<VerificationFailedException>(async () =>
        {
            await using var archive = await ElectionRecord.OpenAsync(zip);
            await archive.ReadSetupAsync();
        });

        Assert.True(RecordCodes.Container == failure.SubSection, $"{corruption}: {failure.SubSection} {failure.Message}");
        Assert.Contains(message, failure.Message);
    }

    private const string Segment = "an empty, '.' or '..' path segment";
    private const string Relative = "is not a relative '/'-separated name";
    private const string CaseFold = "are the same name under case folding";
    private const string Duplicate = "two entries are named";

    /// <summary>
    /// Entries added to a converted archive, and the message that names the rule refusing them. The
    /// names under <c>derived/</c> (which the layout accepts without looking at any table) and the
    /// directory entries (which the layout never sees) are refused only by the rule under test, so
    /// each of those rows fails if its rule is removed.
    /// </summary>
    public static TheoryData<string[], string> BadNames() => new()
    {
        { ["../setup/evil.binpb"], Segment },
        { ["setup/./header2.binpb"], Segment },
        { ["setup\\other.binpb"], Relative },
        { ["/toc2.binpb"], Relative },
        { ["setup//x.binpb"], Segment },
        { ["TOC.binpb"], CaseFold },
        { ["setup/header.binpb"], Duplicate },
        { ["devices/regular-ABCDEF/00000000.binpb"], "is not in the record layout" },
        { ["derived/../toc.binpb"], Segment },
        { ["derived/../../evil.txt"], Segment },
        { ["derived/./x.txt"], Segment },
        { ["derived/x\\y.txt"], Relative },
        { ["derived/A.txt", "derived/a.txt"], CaseFold },
        { ["derived/x.txt", "derived/x.txt"], Duplicate },
        { ["../evil/"], Segment },
        { ["derived/../../evil/"], Segment },
        { ["/evil/"], Relative },
        { ["/"], Relative },
        { ["derived\\evil/"], Relative },
        { ["TOC.BINPB/"], CaseFold },
        { ["derived/X/", "derived/x/"], CaseFold },
        { ["derived/x/", "derived/x/"], Duplicate },
    };

    /// <summary>
    /// Names outside the layout (traversal, '.', backslash, absolute, empty segment), a name equal to
    /// another under case folding, a duplicate name and uppercase hex are refused when the archive is
    /// opened, before anything is extracted or read; so are directory entries (names ending in '/',
    /// added without content) that break the same naming rules. The message names the rule.
    /// </summary>
    [Theory]
    [MemberData(nameof(BadNames))]
    public async Task ArchiveWithANameOutsideTheLayout_IsRefusedAsRContainer(string[] names, string rule)
    {
        string zip = await Zip(RecordEncoding.Protobuf);
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Update))
        {
            foreach (var name in names)
            {
                var entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
                if (!name.EndsWith('/'))
                {
                    using var stream = entry.Open();
                    stream.Write("x"u8);
                }
            }
        }

        var failure = await Assert.ThrowsAsync<VerificationFailedException>(async () => await (await ElectionRecord.OpenAsync(zip)).DisposeAsync());
        Assert.Equal(RecordCodes.Container, failure.SubSection);
        Assert.Contains(rule, failure.Message);
    }

    private const string NotEmptyStored = "is not an empty STORED entry";

    public static TheoryData<string, string?> DirectoryEntryNegatives() => new()
    {
        { "none", null },
        { "the central directory's method made 8", NotEmptyStored },
        { "the central directory's compressed size made 5", NotEmptyStored },
        { "the central directory's size made 5", NotEmptyStored },
        { "the central directory's encryption bit set", NotEmptyStored },
        { "the local header's method made 8", "local header gives method 8" },
        { "the local header's name changed", "local header names" },
        { "the central directory's local header offset past the data", "local header is outside the archive's data" },
    };

    /// <summary>
    /// A directory entry is ignored, but it may not hide data or disagree with its local header: it
    /// must be STORED, empty (both sizes 0), not encrypted, with a local header inside the data that
    /// agrees with it. An archive with a well-formed one reads the same record. Each row asserts the
    /// message of the rule that refuses it.
    /// </summary>
    [Theory]
    [MemberData(nameof(DirectoryEntryNegatives))]
    public async Task ADirectoryEntry_ThatCouldHideDataOrDisagree_IsRefusedAsRContainer(string negative, string? message)
    {
        string zip = await Zip(RecordEncoding.Protobuf);
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Update))
        {
            archive.CreateEntry("derived/notes/", CompressionLevel.NoCompression);
        }

        byte[] bytes = File.ReadAllBytes(zip);
        var (central, local, _) = Locate(bytes, "derived/notes/");
        Assert.Equal(0, BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(central + 10)));
        switch (negative)
        {
            case "the central directory's method made 8": BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(central + 10), 8); break;
            case "the central directory's compressed size made 5": BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(central + 20), 5); break;
            case "the central directory's size made 5": BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(central + 24), 5); break;
            case "the central directory's encryption bit set": bytes[central + 8] |= 0x01; break;
            case "the local header's method made 8": BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(local + 8), 8); break;
            case "the local header's name changed": bytes[local + 30 + "derived/".Length] = (byte)'N'; break;
            case "the central directory's local header offset past the data": BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(central + 42), (uint)central); break;
        }

        File.WriteAllBytes(zip, bytes);
        if (negative == "none")
        {
            await using var archive = await ElectionRecord.OpenAsync(zip);
            await using var directory = await ElectionRecord.OpenAsync(Directory.Value);
            Assert.Equal((await ElectionRecord.CheckClaimedTocAsync(directory)).Entries, (await ElectionRecord.CheckClaimedTocAsync(archive)).Entries);
            return;
        }

        var failure = await Assert.ThrowsAsync<VerificationFailedException>(async () => await (await ElectionRecord.OpenAsync(zip)).DisposeAsync());
        Assert.True(RecordCodes.Container == failure.SubSection, $"{negative}: {failure.SubSection} {failure.Message}");
        Assert.Contains("derived/notes/", failure.Message);
        Assert.Contains(message!, failure.Message);
    }

    public static TheoryData<string, string> AgreeingHeaderNegatives() => new()
    {
        { "a directory entry DEFLATEd in both headers", NotEmptyStored },
        { "a directory entry carrying 5 bytes in both headers", NotEmptyStored },
        { "a file entry with method 12 in both headers", "only STORED (0) and DEFLATE (8) are allowed" },
        { "a STORED file entry whose compressed size is one more than its size in both headers", "has a compressed size" },
    };

    /// <summary>
    /// The rules on an entry's own values, broken in the central directory and the local header
    /// alike (and, where it carries data, with the data and CRC to match), so that the local-header
    /// comparison agrees and only the rule under test can refuse the archive: a directory entry may
    /// not be DEFLATEd or carry bytes, a file entry may use only STORED or DEFLATE, and a STORED
    /// entry's compressed size is its size.
    /// </summary>
    [Theory]
    [MemberData(nameof(AgreeingHeaderNegatives))]
    public async Task AnEntryBreakingARule_WithAgreeingHeaders_IsRefusedByThatRule(string negative, string message)
    {
        string zip = await Zip(RecordEncoding.Protobuf);
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Update))
        {
            archive.CreateEntry("derived/notes/", CompressionLevel.NoCompression);
        }

        var entries = ZipParts.Parse(File.ReadAllBytes(zip));
        int directory = entries.FindIndex(x => x.NameText == "derived/notes/");
        int file = entries.FindIndex(x => x.NameText == "setup/parameters.binpb");
        switch (negative)
        {
            case "a directory entry DEFLATEd in both headers":
                entries[directory] = entries[directory].With(method: 8);
                break;
            case "a directory entry carrying 5 bytes in both headers":
                byte[] hidden = "hello"u8.ToArray();
                entries[directory] = entries[directory].With(data: hidden, size: hidden.Length, compressed: hidden.Length, crc: ~ElectionGuard.Core.RecordFormat.Crc32.Update(0xFFFFFFFF, hidden));
                break;
            case "a file entry with method 12 in both headers":
                entries[file] = entries[file].With(method: 12);
                break;
            case "a STORED file entry whose compressed size is one more than its size in both headers":
                entries[file] = entries[file].With(data: [.. entries[file].Data, 0], compressed: entries[file].Compressed + 1);
                break;
        }

        File.WriteAllBytes(zip, ZipParts.Build(entries, zip64: false));
        var failure = await Assert.ThrowsAsync<VerificationFailedException>(async () =>
        {
            await using var archive = await ElectionRecord.OpenAsync(zip);
            await archive.ReadSetupAsync();
        });

        Assert.True(RecordCodes.Container == failure.SubSection, $"{negative}: {failure.SubSection} {failure.Message}");
        Assert.Contains(message, failure.Message);
    }

    /// <summary>
    /// A local header with the data-descriptor flag (bit 3) may give its CRC and sizes as zero
    /// (design §5.4): the central directory's values govern, and the data is checked against them as
    /// it is read, so the archive reads the same record. Bit 3 does not excuse a local value that is
    /// given and differs.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ALocalHeaderWithADataDescriptor_MayZeroItsCrcAndSizes_ButNotGiveOthers(bool onlyTheCrcZeroed)
    {
        string zip = await Zip(RecordEncoding.Protobuf);
        var entries = ZipParts.Parse(File.ReadAllBytes(zip));
        int target = entries.FindIndex(x => x.NameText == "setup/parameters.binpb");
        var entry = entries[target];
        byte[] local = [.. entry.Local];
        BinaryPrimitives.WriteUInt16LittleEndian(local.AsSpan(6), (ushort)(BinaryPrimitives.ReadUInt16LittleEndian(local.AsSpan(6)) | 0x0008));
        BinaryPrimitives.WriteUInt32LittleEndian(local.AsSpan(14), 0);
        if (!onlyTheCrcZeroed)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(local.AsSpan(18), 0);
            BinaryPrimitives.WriteUInt32LittleEndian(local.AsSpan(22), 0);
        }

        // The descriptor itself (signature, CRC, sizes) follows the data; the reader does not read it.
        byte[] descriptor = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(descriptor, 0x08074b50);
        entry.Central.AsSpan(16, 12).CopyTo(descriptor.AsSpan(4));
        entries[target] = entry with { Local = local, Descriptor = descriptor };
        File.WriteAllBytes(zip, ZipParts.Build(entries, zip64: false));

        if (onlyTheCrcZeroed)
        {
            // A file entry's local header is checked when the entry is read.
            var failure = await Assert.ThrowsAsync<VerificationFailedException>(async () =>
            {
                await using var refused = await ElectionRecord.OpenAsync(zip);
                await refused.ReadSetupAsync();
            });
            Assert.Equal(RecordCodes.Container, failure.SubSection);
            Assert.Contains("disagrees with the central directory", failure.Message);
            return;
        }

        await using var archive = await ElectionRecord.OpenAsync(zip);
        await using var directory = await ElectionRecord.OpenAsync(Directory.Value);
        Assert.Equal((await ElectionRecord.CheckClaimedTocAsync(directory)).Entries, (await ElectionRecord.CheckClaimedTocAsync(archive)).Entries);
        Assert.Equal((await ReadAsync(directory)).Setup.ManifestFile.Bytes, (await ReadAsync(archive)).Setup.ManifestFile.Bytes);
    }

    /// <summary>Every name of a record is printable ASCII (§5.3.1), <c>derived/</c> included; a zip entry name with another byte is refused before it is decoded.</summary>
    [Theory]
    [InlineData("derived/café.txt")]
    [InlineData("derived/x\u007f.txt")]
    public async Task AnEntryNameThatIsNotPrintableAscii_IsRefusedAsRContainer(string name)
    {
        string zip = await Zip(RecordEncoding.Protobuf);
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Update))
        {
            using var stream = archive.CreateEntry(name, CompressionLevel.NoCompression).Open();
            stream.Write("x"u8);
        }

        var failure = await Assert.ThrowsAsync<VerificationFailedException>(async () => await (await ElectionRecord.OpenAsync(zip)).DisposeAsync());
        Assert.Equal(RecordCodes.Container, failure.SubSection);
        Assert.Contains("printable ASCII", failure.Message);
    }

    // ---- the directory and end records, and ZIP64 -----------------------------------------------------

    /// <summary>
    /// An archive rebuilt by hand with every entry in ZIP64 form (sizes and offsets 0xFFFFFFFF with
    /// the ZIP64 extra field, in the central directory and the local headers, and a ZIP64
    /// end-of-central-directory record and locator) reads with the same roots; so does the same
    /// rebuild without ZIP64, which checks the rebuilding itself.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RebuiltArchive_WithOrWithoutZip64_ReadsTheSameRecord(bool zip64)
    {
        string zip = await Zip(RecordEncoding.Protobuf);
        var entries = ZipParts.Parse(File.ReadAllBytes(zip));
        File.WriteAllBytes(zip, ZipParts.Build(zip64 ? entries.Select(x => x.AsZip64()).ToList() : entries, zip64));

        await using var directory = await ElectionRecord.OpenAsync(Directory.Value);
        await using var archive = await ElectionRecord.OpenAsync(zip);
        Assert.Equal((await ElectionRecord.CheckClaimedTocAsync(directory)).Entries, (await ElectionRecord.CheckClaimedTocAsync(archive)).Entries);
        await ReadAsync(archive);
    }

    public static TheoryData<string> DirectoryNegatives() => new()
    {
        // Readers that walk the directory by its size and readers that walk it by count, or that
        // locate it from the end record differently, must not see different entry sets (§5.4).
        "a duplicate entry after the stated count",
        "16 bytes between the central directory and its end record",
        "the end record's two entry counts unequal",
        "an end-of-central-directory signature in the comment",
        // ZIP64 (APPNOTE 4.3.14-4.3.15, 4.5.3).
        "ZIP64: a start disk of 0xFFFF",
        "ZIP64: a local field too short for both sizes",
        "ZIP64: a central value marked with no ZIP64 field",
        "ZIP64: a central field too short for its marked values",
        "ZIP64: an extra field running past the extra data",
        "ZIP64: the 32-bit entry count unlike the ZIP64 record's",
        "ZIP64: the locator pointing elsewhere",
        "ZIP64: the marker without a locator",
        "ZIP64: a compressed size near 2^63",
    };

    [Theory]
    [MemberData(nameof(DirectoryNegatives))]
    public async Task ArchiveWhoseDirectoryOrZip64RecordsDisagree_IsRefusedAsRContainer(string negative)
    {
        string zip = await Zip(RecordEncoding.Protobuf);
        var entries = ZipParts.Parse(File.ReadAllBytes(zip));
        bool zip64 = negative.StartsWith("ZIP64", StringComparison.Ordinal);
        if (zip64)
        {
            entries = entries.Select(x => x.AsZip64()).ToList();
        }

        int target = entries.FindIndex(x => x.NameText == "setup/parameters.binpb");
        int? statedCount = null;
        switch (negative)
        {
            case "a duplicate entry after the stated count":
                statedCount = entries.Count;
                entries.Add(entries[entries.FindIndex(x => x.NameText == "setup/header.binpb")] with { });
                break;
            case "ZIP64: a start disk of 0xFFFF":
                BinaryPrimitives.WriteUInt16LittleEndian(entries[target].Central.AsSpan(34), 0xFFFF);
                break;
            case "ZIP64: a local field too short for both sizes":
                entries[target] = entries[target] with { LocalExtra = ZipParts.Zip64Field(entries[target].Size) };
                break;
            case "ZIP64: a central value marked with no ZIP64 field":
                entries[target] = entries[target] with { CentralExtra = [] };
                break;
            case "ZIP64: a central field too short for its marked values":
                entries[target] = entries[target] with { CentralExtra = ZipParts.Zip64Field(entries[target].Size, entries[target].Compressed) };
                break;
            case "ZIP64: an extra field running past the extra data":
                byte[] runs = [.. entries[target].CentralExtra];
                BinaryPrimitives.WriteUInt16LittleEndian(runs.AsSpan(2), 255);
                entries[target] = entries[target] with { CentralExtra = runs };
                break;
            case "ZIP64: a compressed size near 2^63":
                // Central and local agree on it (a STORED entry: size and compressed size equal), so
                // only the bounds check refuses it, which an unchecked dataOffset + size would wrap past.
                const long huge = long.MaxValue - 8;
                entries[target] = entries[target] with
                {
                    CentralExtra = ZipParts.Zip64Field(huge, huge, 0),
                    LocalExtra = ZipParts.Zip64Field(huge, huge),
                };
                break;
        }

        byte[] bytes = ZipParts.Build(entries, zip64, statedCount);
        int eocd = bytes.Length - 22;
        switch (negative)
        {
            case "16 bytes between the central directory and its end record":
                bytes = [.. bytes[..eocd], .. new byte[16], .. bytes[eocd..]];
                break;
            case "the end record's two entry counts unequal":
                BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(eocd + 8), (ushort)(entries.Count - 1));
                break;
            case "an end-of-central-directory signature in the comment":
                // A comment holding a second end record (and one byte more): readers that take the
                // last signature and readers that take the record ending the file could differ.
                byte[] comment = [.. bytes[eocd..^2], 0, 0, (byte)'x'];
                BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(eocd + 20), (ushort)comment.Length);
                bytes = [.. bytes, .. comment];
                break;
            case "ZIP64: the 32-bit entry count unlike the ZIP64 record's":
                BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(eocd + 8), (ushort)(entries.Count - 1));
                BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(eocd + 10), (ushort)(entries.Count - 1));
                break;
            case "ZIP64: the locator pointing elsewhere":
                BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(eocd - 20 + 8), BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(eocd - 20 + 8)) - 1);
                break;
            case "ZIP64: the marker without a locator":
                bytes[eocd - 20] ^= 0xFF;
                break;
        }

        File.WriteAllBytes(zip, bytes);
        var failure = await Assert.ThrowsAsync<VerificationFailedException>(async () =>
        {
            await using var archive = await ElectionRecord.OpenAsync(zip);
            await ElectionRecord.CheckClaimedTocAsync(archive);
            await ReadAsync(archive);
        });

        Assert.True(RecordCodes.Container == failure.SubSection, $"{negative}: {failure.SubSection} {failure.Message}");
    }

    /// <summary>
    /// A refused archive is not left open: the stream the reader was given is disposed, whether it
    /// was read in place (seekable) or spooled first (the spool file is gone too), and a file opened
    /// by path can be deleted straight away. Disposal is observed on the stream itself, so the test
    /// does not depend on Windows refusing to delete an open file.
    /// </summary>
    [Fact]
    public async Task RefusedArchive_IsNotLeftOpen()
    {
        string zip = await Zip(RecordEncoding.Protobuf);
        byte[] bytes = File.ReadAllBytes(zip);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(bytes.Length - 22 + 8), 1);
        File.WriteAllBytes(zip, bytes);

        var seekable = new DisposeObservingStream(File.OpenRead(zip));
        await Assert.ThrowsAsync<VerificationFailedException>(() => ElectionRecord.OpenAsync(seekable).AsTask());
        Assert.True(seekable.Disposed);

        string spool = TempDirectory("refused-spool");
        var piped = new DisposeObservingStream(new ForwardOnlyStream(File.OpenRead(zip)));
        await Assert.ThrowsAsync<VerificationFailedException>(() => ElectionRecord.OpenAsync(piped, spool).AsTask());
        Assert.True(piped.Disposed);
        Assert.Empty(System.IO.Directory.GetFiles(spool));

        await Assert.ThrowsAsync<VerificationFailedException>(() => ElectionRecord.OpenAsync(zip).AsTask());
        File.Delete(zip);
        Assert.False(File.Exists(zip));
    }

    /// <summary>A stream that passes everything to <paramref name="inner"/> and records whether it was disposed.</summary>
    private sealed class DisposeObservingStream(Stream inner) : Stream
    {
        public bool Disposed { get; private set; }

        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => false;
        public override long Length => inner.Length;

        public override long Position
        {
            get => inner.Position;
            set => inner.Position = value;
        }

        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Disposed = true;
                inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }

    /// <summary>A zip's entries taken apart (an archive without ZIP64, comments or data descriptors, as the converter writes it) and put back together.</summary>
    private sealed record ZipParts(byte[] Central, byte[] Name, byte[] CentralExtra, byte[] Comment, byte[] Local, byte[] LocalExtra, byte[] Data, long Size, long Compressed)
    {
        public string NameText => Encoding.ASCII.GetString(Name);

        /// <summary>Bytes written after the entry's data (a data descriptor); none unless set.</summary>
        public byte[] Descriptor { get; init; } = [];

        /// <summary>This entry with the given values written into both its central and its local header (and its data replaced).</summary>
        public ZipParts With(ushort? method = null, byte[]? data = null, long? size = null, long? compressed = null, uint? crc = null)
        {
            byte[] central = [.. Central], local = [.. Local];
            if (method is { } m)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(central.AsSpan(10), m);
                BinaryPrimitives.WriteUInt16LittleEndian(local.AsSpan(8), m);
            }

            if (crc is { } c)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(central.AsSpan(16), c);
                BinaryPrimitives.WriteUInt32LittleEndian(local.AsSpan(14), c);
            }

            if (compressed is { } z)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(central.AsSpan(20), (uint)z);
                BinaryPrimitives.WriteUInt32LittleEndian(local.AsSpan(18), (uint)z);
            }

            if (size is { } s)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(central.AsSpan(24), (uint)s);
                BinaryPrimitives.WriteUInt32LittleEndian(local.AsSpan(22), (uint)s);
            }

            return this with { Central = central, Local = local, Data = data ?? Data, Size = size ?? Size, Compressed = compressed ?? Compressed };
        }

        public static List<ZipParts> Parse(byte[] bytes)
        {
            int eocd = bytes.Length - 22;
            Assert.Equal(0x06054b50u, BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(eocd)));
            int count = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(eocd + 10));
            int position = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(eocd + 16));
            var entries = new List<ZipParts>();
            for (int i = 0; i < count; i++)
            {
                byte[] central = bytes[position..(position + 46)];
                int n = BinaryPrimitives.ReadUInt16LittleEndian(central.AsSpan(28)), e = BinaryPrimitives.ReadUInt16LittleEndian(central.AsSpan(30)), c = BinaryPrimitives.ReadUInt16LittleEndian(central.AsSpan(32));
                int local = (int)BinaryPrimitives.ReadUInt32LittleEndian(central.AsSpan(42));
                int ln = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(local + 26)), le = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(local + 28));
                long compressed = BinaryPrimitives.ReadUInt32LittleEndian(central.AsSpan(20));
                int data = local + 30 + ln + le;
                entries.Add(new ZipParts(
                    central,
                    bytes[(position + 46)..(position + 46 + n)],
                    bytes[(position + 46 + n)..(position + 46 + n + e)],
                    bytes[(position + 46 + n + e)..(position + 46 + n + e + c)],
                    bytes[local..(local + 30)],
                    bytes[(local + 30 + ln)..data],
                    bytes[data..(data + (int)compressed)],
                    BinaryPrimitives.ReadUInt32LittleEndian(central.AsSpan(24)),
                    compressed));
                position += 46 + n + e + c;
            }

            return entries;
        }

        /// <summary>A ZIP64 extended information field (0x0001) holding <paramref name="values"/>.</summary>
        public static byte[] Zip64Field(params long[] values)
        {
            byte[] field = new byte[4 + 8 * values.Length];
            BinaryPrimitives.WriteUInt16LittleEndian(field, 0x0001);
            BinaryPrimitives.WriteUInt16LittleEndian(field.AsSpan(2), (ushort)(8 * values.Length));
            for (int i = 0; i < values.Length; i++)
            {
                BinaryPrimitives.WriteInt64LittleEndian(field.AsSpan(4 + 8 * i), values[i]);
            }

            return field;
        }

        /// <summary>This entry in ZIP64 form: sizes (and, centrally, the offset, which <see cref="Build"/> fills in) in the extra fields.</summary>
        public ZipParts AsZip64()
        {
            byte[] central = [.. Central], local = [.. Local];
            BinaryPrimitives.WriteUInt16LittleEndian(central.AsSpan(6), 45);
            BinaryPrimitives.WriteUInt32LittleEndian(central.AsSpan(20), 0xFFFFFFFF);
            BinaryPrimitives.WriteUInt32LittleEndian(central.AsSpan(24), 0xFFFFFFFF);
            BinaryPrimitives.WriteUInt32LittleEndian(central.AsSpan(42), 0xFFFFFFFF);
            BinaryPrimitives.WriteUInt16LittleEndian(local.AsSpan(4), 45);
            BinaryPrimitives.WriteUInt32LittleEndian(local.AsSpan(18), 0xFFFFFFFF);
            BinaryPrimitives.WriteUInt32LittleEndian(local.AsSpan(22), 0xFFFFFFFF);
            return this with { Central = central, Local = local, CentralExtra = [.. Zip64Field(Size, Compressed, 0), .. CentralExtra], LocalExtra = [.. Zip64Field(Size, Compressed), .. LocalExtra] };
        }

        /// <summary>
        /// Lays the entries out again (local headers and data, then the central directory, then, for
        /// ZIP64, the ZIP64 end record and its locator, then the end record). Each entry's local
        /// offset is written where its central header or ZIP64 field keeps it; the end record states
        /// <paramref name="statedCount"/> entries, or all of them.
        /// </summary>
        public static byte[] Build(List<ZipParts> entries, bool zip64, int? statedCount = null)
        {
            var output = new MemoryStream();
            var offsets = new Dictionary<string, long>();
            foreach (var entry in entries.DistinctBy(x => x.NameText))
            {
                offsets[entry.NameText] = output.Position;
                byte[] local = [.. entry.Local];
                BinaryPrimitives.WriteUInt16LittleEndian(local.AsSpan(28), (ushort)entry.LocalExtra.Length);
                output.Write(local);
                output.Write(entry.Name);
                output.Write(entry.LocalExtra);
                output.Write(entry.Data);
                output.Write(entry.Descriptor);
            }

            long cdOffset = output.Position;
            foreach (var entry in entries)
            {
                byte[] central = [.. entry.Central], extra = [.. entry.CentralExtra];
                BinaryPrimitives.WriteUInt16LittleEndian(central.AsSpan(30), (ushort)extra.Length);
                if (BinaryPrimitives.ReadUInt32LittleEndian(central.AsSpan(42)) == 0xFFFFFFFF)
                {
                    // The offset is the ZIP64 field's last value, after the sizes it carries.
                    int marked = (BinaryPrimitives.ReadUInt32LittleEndian(central.AsSpan(24)) == 0xFFFFFFFF ? 1 : 0) + (BinaryPrimitives.ReadUInt32LittleEndian(central.AsSpan(20)) == 0xFFFFFFFF ? 1 : 0);
                    if (extra.Length >= 4 + 8 * (marked + 1) && BinaryPrimitives.ReadUInt16LittleEndian(extra) == 0x0001)
                    {
                        BinaryPrimitives.WriteInt64LittleEndian(extra.AsSpan(4 + 8 * marked), offsets[entry.NameText]);
                    }
                }
                else
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(central.AsSpan(42), (uint)offsets[entry.NameText]);
                }

                output.Write(central);
                output.Write(entry.Name);
                output.Write(extra);
                output.Write(entry.Comment);
            }

            long cdSize = output.Position - cdOffset;
            long count = statedCount ?? entries.Count;
            var writer = new BinaryWriter(output);
            if (zip64)
            {
                long record = output.Position;
                writer.Write(0x06064b50u);
                writer.Write(44UL);
                writer.Write((ushort)45);
                writer.Write((ushort)45);
                writer.Write(0u);
                writer.Write(0u);
                writer.Write((ulong)count);
                writer.Write((ulong)count);
                writer.Write((ulong)cdSize);
                writer.Write((ulong)cdOffset);
                writer.Write(0x07064b50u);
                writer.Write(0u);
                writer.Write((ulong)record);
                writer.Write(1u);
            }

            writer.Write(0x06054b50u);
            writer.Write((ushort)0);
            writer.Write((ushort)0);
            writer.Write(zip64 ? (ushort)0xFFFF : (ushort)count);
            writer.Write(zip64 ? (ushort)0xFFFF : (ushort)count);
            writer.Write(zip64 ? 0xFFFFFFFF : (uint)cdSize);
            writer.Write(zip64 ? 0xFFFFFFFF : (uint)cdOffset);
            writer.Write((ushort)0);
            writer.Flush();
            return output.ToArray();
        }
    }

    private static int LocalMethod(string zip, string name)
    {
        byte[] bytes = File.ReadAllBytes(zip);
        var (_, local, _) = Locate(bytes, name);
        return BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(local + 8));
    }

    /// <summary>The offsets of an entry's central directory header, local header and data.</summary>
    private static (int Central, int Local, int Data) Locate(byte[] bytes, string name)
    {
        byte[] nameBytes = Encoding.ASCII.GetBytes(name);
        for (int i = 0; i + 46 < bytes.Length; i++)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i)) == 0x02014b50
                && BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(i + 28)) == nameBytes.Length
                && bytes.AsSpan(i + 46, nameBytes.Length).SequenceEqual(nameBytes))
            {
                int local = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i + 42));
                int data = local + 30 + BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(local + 26)) + BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(local + 28));
                return (i, local, data);
            }
        }

        throw new InvalidOperationException($"No central directory entry {name}.");
    }

    /// <summary>A stream that reads forward only (a pipe, say): CanSeek is false and Seek throws.</summary>
    internal sealed class ForwardOnlyStream(Stream inner) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
