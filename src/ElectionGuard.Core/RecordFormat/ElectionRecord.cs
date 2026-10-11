using System.Runtime.CompilerServices;
using ElectionGuard.Core.Models;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.RecordFormat;

/// <summary>How two records differ (<see cref="ElectionRecord.DiffAsync"/>).</summary>
public enum RecordDifferenceKind
{
    /// <summary>The records are at different phases.</summary>
    Phase,

    /// <summary>A section only the first record holds.</summary>
    SectionOnlyInA,

    /// <summary>A section only the second record holds.</summary>
    SectionOnlyInB,

    /// <summary>An item both sections hold at this ordinal, with different bytes.</summary>
    ItemChanged,

    /// <summary>An item past the end of the second record's section.</summary>
    ItemOnlyInA,

    /// <summary>An item past the end of the first record's section.</summary>
    ItemOnlyInB,
}

/// <summary>One difference between two records: where it is, and the two leaf hashes when it is an item.</summary>
public sealed record RecordDifference(RecordDifferenceKind Kind, SectionKey? Section, long? Ordinal, Sha256Digest? LeafA, Sha256Digest? LeafB, string Message);

/// <summary>
/// The entry points of the election record format's carriers (design §8.3): open a record in a
/// directory or a <c>.zip</c>, in either encoding; create one with the phase-gated writer; compute
/// and check its table of contents; convert it between representations; and diff two records.
/// </summary>
public static class ElectionRecord
{
    /// <summary>
    /// Opens the record at <paramref name="path"/>: a directory, or a <c>.zip</c> file. Throws a
    /// <see cref="Verify.VerificationFailedException"/> with an R-code (<see cref="RecordCodes"/>)
    /// for a layout, version or presence failure.
    /// </summary>
    public static async ValueTask<IElectionRecordReader> OpenAsync(string path, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        if (Directory.Exists(path))
        {
            return await ElectionRecordReader.OpenAsync(new DirectoryRecordSource(path), ct).ConfigureAwait(false);
        }

        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16, FileOptions.RandomAccess);
        return await OpenAsync(stream, null, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Opens the <c>.zip</c> record in <paramref name="zip"/>, which the reader then owns. A stream
    /// that cannot seek is spooled to a temporary file in <paramref name="spoolDirectory"/> first
    /// (user decision NQ-6, design §5.4).
    /// </summary>
    public static async ValueTask<IElectionRecordReader> OpenAsync(Stream zip, string? spoolDirectory = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(zip);
        var source = await ZipRecordSource.OpenAsync(zip, spoolDirectory, ct).ConfigureAwait(false);
        return await ElectionRecordReader.OpenAsync(source, ct).ConfigureAwait(false);
    }

    /// <summary>A phase-gated writer of a new record in <paramref name="directory"/> (empty or absent).</summary>
    public static ElectionRecordWriter Create(string directory, RecordEncoding encoding, ElectionRecordWriterOptions? options = null) =>
        ElectionRecordWriter.Create(directory, encoding, options);

    /// <summary>Resumes the writer of the record in <paramref name="directory"/>, repairing torn tails (<see cref="ElectionRecordWriter.ResumeAsync"/>).</summary>
    public static ValueTask<ElectionRecordWriter> ResumeAsync(string directory, ElectionRecordWriterOptions? options = null, CancellationToken ct = default) =>
        ElectionRecordWriter.ResumeAsync(directory, options, ct);

    /// <summary>
    /// The table of contents of <paramref name="record"/>, recomputed from its items as read (design
    /// §4.9): per section, in canonical order, the item count and the Merkle root of the item bytes.
    /// The critical bit is §4.5's for a standard type and the claimed TOC's for any other (false
    /// without one). Streams one section at a time. A protobuf item that fails the canonicality check
    /// is digested as read (§4.8 layer 1).
    /// </summary>
    public static async ValueTask<TableOfContents> ComputeTocAsync(IElectionRecordReader record, int maxDegreeOfParallelism = -1, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        var entries = new List<TocEntry>();
        foreach (var section in record.Sections)
        {
            var frontier = new MerkleFrontier();
            await foreach (var item in record.ReadSectionAsync(section, 0, ct).ConfigureAwait(false))
            {
                frontier.Append(item.Bytes.Span);
            }

            entries.Add(new TocEntry(section.Type, section.Key.Span, CriticalOf(record, section), frontier.Count, frontier.Root()));
        }

        return new TableOfContents(entries);
    }

    /// <summary>
    /// Recomputes the table of contents and compares it with the claimed one entry by entry (§4.9,
    /// §5.3.1: the TOC never decides membership). Throws <c>R.root</c> naming the first section whose
    /// entry differs (root, count or critical bit), or that one of the two lacks; returns the computed
    /// TOC. A record without a claimed TOC passes with its computed one.
    /// </summary>
    public static async ValueTask<TableOfContents> CheckClaimedTocAsync(IElectionRecordReader record, CancellationToken ct = default)
    {
        var computed = await ComputeTocAsync(record, -1, ct).ConfigureAwait(false);
        if (record.ClaimedToc is { } claimed && ClaimedTocDifferences(computed.Entries, claimed) is { Count: > 0 } differences)
        {
            throw RecordCodes.Failure(RecordCodes.Root, differences[0].Message);
        }

        return computed;
    }

    /// <summary>
    /// Every way the claimed TOC differs from the <paramref name="computed"/> entries (each an
    /// <c>R.root</c> failure), in canonical section order: a section with files and no claimed entry,
    /// an entry whose count, root or critical bit differs, then each claimed section with no files.
    /// With <paramref name="upTo"/>, only sections of that phase or earlier are compared (a verifier
    /// of an aggregated prefix). <see cref="CheckClaimedTocAsync"/> throws the first; the record
    /// verifier reports them all.
    /// </summary>
    internal static IReadOnlyList<(SectionKey Section, string Message)> ClaimedTocDifferences(IEnumerable<TocEntry> computed, TableOfContents claimed, RecordPhase? upTo = null)
    {
        var claimedBySection = claimed.Entries.Where(x => upTo is null || x.Phase <= upTo).ToDictionary(x => new SectionKey(x.Type, x.Key.Span));
        var differences = new List<(SectionKey, string)>();
        foreach (var entry in computed.Where(x => upTo is null || x.Phase <= upTo))
        {
            var section = new SectionKey(entry.Type, entry.Key.Span);
            if (!claimedBySection.Remove(section, out var stated))
            {
                differences.Add((section, $"Section {section} has files but no entry in the claimed TOC (§5.3.1)."));
            }
            else if (!stated.Equals(entry))
            {
                differences.Add((section, $"Section {section}: the claimed TOC states {stated.ItemCount} items, root {stated.Root}, critical {stated.Critical}; the record holds {entry.ItemCount}, root {entry.Root}, critical {entry.Critical} (§4.5, §4.9)."));
            }
        }

        foreach (var section in claimedBySection.Keys.Order())
        {
            differences.Add((section, $"The claimed TOC names section {section}, which has no files (§5.3.1)."));
        }

        return differences;
    }

    /// <summary>The critical bit of <paramref name="section"/> (§4.5): fixed per section type, true for every v2 type.</summary>
    internal static bool CriticalBitOf(IElectionRecordReader record, SectionKey section) => CriticalOf(record, section);

    /// <summary>
    /// Converts <paramref name="source"/> to <paramref name="encoding"/> in <paramref name="carrier"/>
    /// at <paramref name="destination"/> (a new or empty directory, or a new <c>.zip</c> file),
    /// streaming one section at a time, and returns the TOC, whose roots are the source's: a converter
    /// is correct iff it preserves every phase root (design §5.1). Protobuf items are copied byte for
    /// byte (unknown fields of a newer minor survive); content a JSON line cannot carry (an unknown
    /// field, item type or enum value) is refused (<c>R.version</c>), never dropped; a source item that
    /// is not canonical is refused (<c>R.encoding</c>). Signatures, <c>meta.json</c> and the manifest
    /// copy are carried over; <c>derived/</c> is not (it is regenerable, §5.6). A <c>.zip</c> holds the
    /// TOC and the setup first; its JSON entries are DEFLATEd when <paramref name="deflateJson"/>. When
    /// the source claims a TOC, it is written first and checked against the converted sections at the
    /// end (<c>R.root</c>, and the destination is deleted). Conversion is sequential;
    /// <paramref name="maxDegreeOfParallelism"/> is accepted for the API's shape (design §8.3).
    /// <paramref name="source"/> must be a reader <see cref="OpenAsync(string, CancellationToken)"/>
    /// returned: the files outside every root (signatures, <c>meta.json</c>, the manifest copy) are
    /// not on <see cref="IElectionRecordReader"/>, so any other implementation is refused
    /// (<see cref="ArgumentException"/>, before anything is created) rather than converted without them.
    /// </summary>
    public static async ValueTask<TableOfContents> ConvertAsync(IElectionRecordReader source, string destination, RecordEncoding encoding, RecordCarrier carrier,
        int maxDegreeOfParallelism = -1, bool deflateJson = true, long segmentSizeBytes = 256L << 20, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentException.ThrowIfNullOrEmpty(destination);
        var reader = source as ElectionRecordReader ?? throw new ArgumentException(
            $"ConvertAsync converts a record opened with ElectionRecord.OpenAsync; a {source.GetType().Name} cannot hand over the files outside the roots (signatures, meta.json, the manifest copy), which would be lost.",
            nameof(source));
        IRecordSink sink;
        if (carrier == RecordCarrier.Directory)
        {
            if (Directory.Exists(destination) && Directory.EnumerateFileSystemEntries(destination).Any())
            {
                throw new IOException($"{destination} is not empty.");
            }

            Directory.CreateDirectory(destination);
            sink = new DirectoryRecordSink(destination);
        }
        else
        {
            sink = new ZipRecordSink(new FileStream(destination, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 1 << 16), deflateJson);
        }

        bool completed = false;
        try
        {
            var toc = await CopyAsync(reader, sink, encoding, segmentSizeBytes, ct).ConfigureAwait(false);
            completed = true;
            return toc;
        }
        finally
        {
            sink.Dispose();
            if (!completed)
            {
                if (carrier == RecordCarrier.Directory)
                {
                    TryDelete(() => Directory.Delete(destination, recursive: true));
                }
                else
                {
                    TryDelete(() => File.Delete(destination));
                }
            }
        }
    }

    private static async ValueTask<TableOfContents> CopyAsync(ElectionRecordReader source, IRecordSink sink, RecordEncoding encoding, long segmentSizeBytes, CancellationToken ct)
    {
        if (source.ClaimedToc is { } claimed)
        {
            await using var stream = sink.Create(RecordLayout.TocPath(encoding), compressible: encoding == RecordEncoding.Json);
            await ElectionRecordWriter.WriteTocAsync(stream, claimed, encoding, ct).ConfigureAwait(false);
        }

        var entries = new List<TocEntry>();
        bool manifestCopied = false;
        foreach (var section in source.Sections)
        {
            if (!manifestCopied && section.Phase > RecordPhase.Setup)
            {
                await CopyFileAsync(source.ManifestCopyPath, RecordLayout.ManifestCopyPath).ConfigureAwait(false);
                manifestCopied = true;
            }

            await using var writer = new SectionWriter(sink, section, encoding, segmentSizeBytes);
            await foreach (var item in source.ReadSectionAsync(section, 0, ct).ConfigureAwait(false))
            {
                if (!item.Check.IsCanonical)
                {
                    throw RecordCodes.Failure(RecordCodes.Encoding, $"Item {item.Ordinal} of section {section} is not canonical ({item.Check.Rule}): {item.Check.Message}; a record is converted only when every item is.");
                }

                await writer.AppendAsync(item.Bytes, item.Check, ct).ConfigureAwait(false);
            }

            entries.Add(await writer.CompleteAsync(CriticalOf(source, section), ct).ConfigureAwait(false));
        }

        if (!manifestCopied)
        {
            await CopyFileAsync(source.ManifestCopyPath, RecordLayout.ManifestCopyPath).ConfigureAwait(false);
        }

        var toc = new TableOfContents(entries);
        foreach (var path in source.SignatureFiles)
        {
            string name = path[..path.LastIndexOf('.')];
            await using var stream = sink.Create($"{name}.{RecordLayout.Extension(encoding)}", compressible: encoding == RecordEncoding.Json);
            await CopySignaturesAsync(source, path, stream, encoding, ct).ConfigureAwait(false);
        }

        await CopyFileAsync(source.Source.Files.Contains(RecordLayout.MetaPath) ? RecordLayout.MetaPath : null, RecordLayout.MetaPath).ConfigureAwait(false);

        if (source.ClaimedToc is { } stated && !stated.Entries.SequenceEqual(toc.Entries))
        {
            throw RecordCodes.Failure(RecordCodes.Root, "The source's claimed TOC is not the TOC of its sections; the conversion is discarded (§4.9).");
        }

        if (source.ClaimedToc is null)
        {
            await using var stream = sink.Create(RecordLayout.TocPath(encoding), compressible: encoding == RecordEncoding.Json);
            await ElectionRecordWriter.WriteTocAsync(stream, toc, encoding, ct).ConfigureAwait(false);
        }

        return toc;

        async ValueTask CopyFileAsync(string? from, string to)
        {
            if (from is null)
            {
                return;
            }

            await using var input = source.Source.OpenRead(from);
            await using var output = sink.Create(to, compressible: true);
            await input.CopyToAsync(output, ct).ConfigureAwait(false);
        }
    }

    private static async ValueTask CopySignaturesAsync(ElectionRecordReader reader, string path, Stream output, RecordEncoding encoding, CancellationToken ct)
    {
        var header = new Pb.SegmentHeader { Magic = "EGRF", FormatMajor = RecordFormatVersion.Library.Major, SectionType = Pb.SectionType.Signatures };
        if (encoding == RecordEncoding.Protobuf)
        {
            await SegmentFraming.WriteFrameAsync(output, Google.Protobuf.MessageExtensions.ToByteArray(header), ct).ConfigureAwait(false);
        }
        else
        {
            await output.WriteAsync(RecordJson.FormatSegmentHeader(header), ct).ConfigureAwait(false);
            output.WriteByte((byte)'\n');
        }

        await foreach (var item in reader.ReadSegmentAsync(path, new SectionKey((RecordSectionType)0xFFFF, []), 0, reader.Format.Minor, ct).ConfigureAwait(false))
        {
            if (!item.Check.IsCanonical)
            {
                throw RecordCodes.Failure(RecordCodes.Encoding, $"{path}: signature {item.Ordinal} is not canonical ({item.Check.Rule}).");
            }

            if (encoding == RecordEncoding.Protobuf)
            {
                await SegmentFraming.WriteFrameAsync(output, item.Bytes, ct).ConfigureAwait(false);
            }
            else
            {
                await output.WriteAsync(RecordJson.FormatItem(item.Bytes.Span, item.Check), ct).ConfigureAwait(false);
                output.WriteByte((byte)'\n');
            }
        }
    }

    /// <summary>
    /// The ballots of <paramref name="record"/> whose confirmation code H_C is <paramref name="code"/>
    /// (design §5.6: the confirmation-code lookup a voter's tool needs), as locators in canonical
    /// order: every ballot item of every kind and status in every device section, read in full (a
    /// scan; the <c>derived/</c> lookup index is not read, it is outside every root). Normally one;
    /// none when the record holds no such ballot. An item that is not canonical is skipped (its section
    /// fails verification anyway); a section that cannot be read throws, as reading it does.
    /// </summary>
    public static async IAsyncEnumerable<BallotLocator> FindBallotsAsync(IElectionRecordReader record, ConfirmationCode code, [EnumeratorCancellation] CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        byte[] wanted = code;
        foreach (var device in record.Devices)
        {
            await foreach (var item in record.ReadSectionAsync(SectionKey.Device(device), 0, ct).ConfigureAwait(false))
            {
                if (!item.Check.IsCanonical)
                {
                    continue;
                }

                var parsed = Pb.RecordItem.Parser.ParseFrom(item.Bytes.Span);
                var stated = parsed.ItemCase switch
                {
                    Pb.RecordItem.ItemOneofCase.EncryptedBallot => parsed.EncryptedBallot.ConfirmationCode,
                    Pb.RecordItem.ItemOneofCase.PreEncryptedCastBallot => parsed.PreEncryptedCastBallot.ConfirmationCode,
                    Pb.RecordItem.ItemOneofCase.PreEncryptedUncastBallot => parsed.PreEncryptedUncastBallot.ConfirmationCode,
                    Pb.RecordItem.ItemOneofCase.PreEncryptedCompactUncastBallot => parsed.PreEncryptedCompactUncastBallot.ConfirmationCode,
                    _ => null,
                };

                // A ballot's ordinal in its section is its chain position j: the header is item 0.
                if (stated is not null && stated.Span.SequenceEqual(wanted))
                {
                    yield return new BallotLocator(device, item.Ordinal);
                }
            }
        }
    }

    /// <summary>
    /// The differences between two records, by descent from the roots (design §5.1, §8.3): the TOCs
    /// are recomputed, sections whose entries are equal are skipped unread, and only sections whose
    /// roots differ are read, both at once, item by item, comparing leaf hashes. Yields the phase if
    /// it differs, each section only one record holds, and each item that differs or that only one
    /// section holds. An empty sequence means the two records are equivalent: same logical record,
    /// same roots, whatever their encodings and carriers.
    /// </summary>
    public static async IAsyncEnumerable<RecordDifference> DiffAsync(IElectionRecordReader a, IElectionRecordReader b, [EnumeratorCancellation] CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);
        var tocA = await ComputeTocAsync(a, -1, ct).ConfigureAwait(false);
        var tocB = await ComputeTocAsync(b, -1, ct).ConfigureAwait(false);
        if (tocA.Root == tocB.Root && tocA.Phase == tocB.Phase)
        {
            yield break;
        }

        if (tocA.Phase != tocB.Phase)
        {
            yield return new RecordDifference(RecordDifferenceKind.Phase, null, null, null, null, $"The first record is at phase {tocA.Phase}, the second at {tocB.Phase}.");
        }

        var entriesB = tocB.Entries.ToDictionary(x => new SectionKey(x.Type, x.Key.Span));
        foreach (var entryA in tocA.Entries)
        {
            var section = new SectionKey(entryA.Type, entryA.Key.Span);
            if (!entriesB.Remove(section, out var entryB))
            {
                yield return new RecordDifference(RecordDifferenceKind.SectionOnlyInA, section, null, null, null, $"Section {section} ({entryA.ItemCount} items) is only in the first record.");
                continue;
            }

            if (entryA.Equals(entryB))
            {
                continue;
            }

            await foreach (var difference in DiffSectionAsync(a, b, section, ct).ConfigureAwait(false))
            {
                yield return difference;
            }
        }

        foreach (var entryB in entriesB.Values.OrderBy(x => x, Comparer<TocEntry>.Create(TocEntry.CompareSections)))
        {
            var section = new SectionKey(entryB.Type, entryB.Key.Span);
            yield return new RecordDifference(RecordDifferenceKind.SectionOnlyInB, section, null, null, null, $"Section {section} ({entryB.ItemCount} items) is only in the second record.");
        }
    }

    private static async IAsyncEnumerable<RecordDifference> DiffSectionAsync(IElectionRecordReader a, IElectionRecordReader b, SectionKey section, [EnumeratorCancellation] CancellationToken ct)
    {
        await using var itemsA = a.ReadSectionAsync(section, 0, ct).GetAsyncEnumerator(ct);
        await using var itemsB = b.ReadSectionAsync(section, 0, ct).GetAsyncEnumerator(ct);
        long ordinal = 0;
        while (true)
        {
            bool hasA = await itemsA.MoveNextAsync().ConfigureAwait(false);
            bool hasB = await itemsB.MoveNextAsync().ConfigureAwait(false);
            if (!hasA && !hasB)
            {
                yield break;
            }

            Sha256Digest? leafA = hasA ? MerkleTree.LeafHash(itemsA.Current.Bytes.Span) : null;
            Sha256Digest? leafB = hasB ? MerkleTree.LeafHash(itemsB.Current.Bytes.Span) : null;
            if (leafA != leafB)
            {
                var kind = !hasB ? RecordDifferenceKind.ItemOnlyInA : !hasA ? RecordDifferenceKind.ItemOnlyInB : RecordDifferenceKind.ItemChanged;
                yield return new RecordDifference(kind, section, ordinal, leafA, leafB, $"Section {section}, item {ordinal}: {kind}.");
            }

            ordinal++;
        }
    }

    private static bool CriticalOf(IElectionRecordReader record, SectionKey section) =>
        RecordSections.FixedCritical(section.Type) ?? throw new InvalidOperationException($"Section {section} is not a section type of EGRF v2; the reader admits no other (NQ-7).");

    private static void TryDelete(Action delete)
    {
        try
        {
            delete();
        }
        catch (IOException)
        {
            // Best effort: a partial conversion that cannot be removed is left for the caller.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
