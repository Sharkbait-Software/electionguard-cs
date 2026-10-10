using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat.Mappers;
using ElectionGuard.Core.Verify;
using System.Runtime.CompilerServices;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.RecordFormat;

/// <summary>
/// A record opened for reading (design §8.3), in either carrier and either encoding. Opening checks
/// the layout (§5.3.1: names, no unlisted file, one encoding, contiguous segments; <c>R.container</c>),
/// the format version (the header item; another major is <c>R.version</c>) and the presence and phase
/// rules (§4.5; <c>R.structure</c>). Sections are read on demand and streamed: segment by segment,
/// frame by frame (or line by line), each segment header checked (D6, path agreement and first
/// ordinals, <c>R.container</c>) and each item's canonicality checked and handed on with it. Memory is
/// one item at a time, never a section. The claimed table of contents is read, kept, and never trusted.
/// </summary>
public interface IElectionRecordReader : IAsyncDisposable
{
    RecordEncoding Encoding { get; }

    RecordCarrier Carrier { get; }

    /// <summary>The record's format version, from its header item.</summary>
    RecordFormatVersion Format { get; }

    /// <summary>The record's phase: the latest phase whose required sections are all present (§4.5).</summary>
    RecordPhase Phase { get; }

    /// <summary>The stored table of contents, or null when the record has none. A claim: recompute it (<see cref="ElectionRecord.ComputeTocAsync"/>).</summary>
    TableOfContents? ClaimedToc { get; }

    /// <summary>Every section the layout holds, in canonical order.</summary>
    IReadOnlyList<SectionKey> Sections { get; }

    /// <summary>The device sections' keys, in canonical order.</summary>
    IReadOnlyList<DeviceKey> Devices { get; }

    /// <summary>
    /// The setup sections as domain values (§3.1). Throws <see cref="VerificationFailedException"/>:
    /// <c>R.encoding</c> for a non-canonical item, <c>R.structure</c> for items that are not the setup's,
    /// a range finding under its own code (design §4.8), and <c>R.container</c> when a
    /// <c>setup/manifest.json</c> copy is not byte-identical to the stored manifest.
    /// </summary>
    ValueTask<RecordSetup> ReadSetupAsync(CancellationToken ct = default);

    /// <summary>A device section's reader.</summary>
    IDeviceSectionReader OpenDevice(DeviceKey device);

    /// <summary>The items of <paramref name="section"/> from ordinal <paramref name="fromOrdinal"/>, streamed.</summary>
    IAsyncEnumerable<RecordItemBytes> ReadSectionAsync(SectionKey section, long fromOrdinal = 0, CancellationToken ct = default);

    /// <summary>The record signatures (the signatures pseudo-section, outside every root), file by file.</summary>
    IAsyncEnumerable<RecordItemBytes> ReadSignaturesAsync(CancellationToken ct = default);
}

/// <summary>A device section (design §4.5): its header, its ballot items in chain order, and its close.</summary>
public interface IDeviceSectionReader
{
    DeviceKey Key { get; }

    /// <summary>The <c>device_header</c>, the section's first item; it must name the section's key.</summary>
    ValueTask<DeviceHeader> ReadHeaderAsync(CancellationToken ct = default);

    /// <summary>The ballot items, ordinals 1..ℓ (an item's ordinal is its chain position, its locator's position).</summary>
    IAsyncEnumerable<RecordItemBytes> ReadEntriesAsync(CancellationToken ct = default);

    /// <summary>The <c>device_close</c>, the section's last item; null while the device is still live.</summary>
    ValueTask<DeviceClose?> ReadCloseAsync(CancellationToken ct = default);
}

/// <summary>The reader of both carriers and both encodings (see <see cref="IElectionRecordReader"/>).</summary>
internal sealed class ElectionRecordReader : IElectionRecordReader
{
    private readonly IRecordSource _source;
    private readonly Dictionary<SectionKey, List<string>> _segments;
    private readonly List<string> _signatureFiles;

    private ElectionRecordReader(IRecordSource source, RecordEncoding encoding, Dictionary<SectionKey, List<string>> segments, List<string> signatureFiles, string? tocPath, string? manifestCopy, bool checkPresence)
    {
        _source = source;
        Encoding = encoding;
        _segments = segments;
        _signatureFiles = signatureFiles;
        TocPath = tocPath;
        ManifestCopyPath = manifestCopy;
        Sections = segments.Keys.Order().ToList();
        Devices = Sections.Where(x => x.Type == RecordSectionType.Device).Select(x => DeviceKeyOf(x.Key.Span)).ToList();
        Phase = checkPresence ? PhaseOf(Sections) : RecordPhase.Setup;
    }

    public RecordEncoding Encoding { get; }

    public RecordCarrier Carrier => _source.Carrier;

    public RecordFormatVersion Format { get; private set; }

    public RecordPhase Phase { get; }

    public TableOfContents? ClaimedToc { get; private set; }

    public IReadOnlyList<SectionKey> Sections { get; }

    public IReadOnlyList<DeviceKey> Devices { get; }

    internal string? TocPath { get; }

    internal string? ManifestCopyPath { get; }

    internal IRecordSource Source => _source;

    /// <summary>
    /// Opens the record in <paramref name="source"/>: checks the layout, reads the format version from
    /// the header item, and the presence and phase rules; reads the claimed TOC if there is one. The
    /// reader owns the source.
    /// </summary>
    public static async ValueTask<ElectionRecordReader> OpenAsync(IRecordSource source, CancellationToken ct, bool checkPresence = true)
    {
        try
        {
            var reader = Layout(source, checkPresence);
            await reader.ReadFormatAsync(ct).ConfigureAwait(false);
            await reader.ReadClaimedTocAsync(ct).ConfigureAwait(false);
            return reader;
        }
        catch
        {
            source.Dispose();
            throw;
        }
    }

    private static ElectionRecordReader Layout(IRecordSource source, bool checkPresence)
    {
        RecordLayout.RequireNoCaseFoldCollision(source.Files);
        var files = source.Files.Select(RecordLayout.Parse).ToList();
        var extensions = files.Where(x => x.Extension is not null).Select(x => x.Extension!).Distinct().ToList();
        if (extensions.Count > 1)
        {
            throw RecordCodes.Failure(RecordCodes.Container, "The record mixes .binpb and .jsonl files; every section file of a record has one encoding (§5.3.1).");
        }

        if (extensions.Count == 0)
        {
            throw RecordCodes.Failure(RecordCodes.Structure, "The location holds no record sections.");
        }

        var segments = new Dictionary<SectionKey, List<string>>();
        foreach (var group in files.Where(x => x.Kind == LayoutFileKind.Segment).GroupBy(x => x.Section))
        {
            var ordered = group.OrderBy(x => x.SegmentIndex).ToList();
            for (int i = 0; i < ordered.Count; i++)
            {
                if (ordered[i].SegmentIndex != i)
                {
                    throw RecordCodes.Failure(RecordCodes.Container, $"Section {group.Key}'s segments are not numbered 00000000 upward with no gap (missing segment {i}; §5.3.1).");
                }
            }

            segments[group.Key] = ordered.Select(x => x.Path).ToList();
        }

        string? toc = files.SingleOrDefault(x => x.Kind == LayoutFileKind.Toc)?.Path;
        string? manifestCopy = files.SingleOrDefault(x => x.Kind == LayoutFileKind.ManifestCopy)?.Path;
        var signatures = files.Where(x => x.Kind == LayoutFileKind.Signature).Select(x => x.Path).Order(StringComparer.Ordinal).ToList();
        return new ElectionRecordReader(source, RecordLayout.EncodingOf(extensions[0]), segments, signatures, toc, manifestCopy, checkPresence);
    }

    /// <summary>The phase of a record holding <paramref name="sections"/>; <c>R.structure</c> unless it holds every required section of its phase and earlier ones (§4.5).</summary>
    private static RecordPhase PhaseOf(IReadOnlyList<SectionKey> sections)
    {
        var types = sections.Select(x => x.Type).ToHashSet();
        RecordSectionType[] setup = [RecordSectionType.Header, RecordSectionType.Parameters, RecordSectionType.Manifest, RecordSectionType.Guardians, RecordSectionType.ElectionKeys];
        RecordSectionType[] aggregated = [RecordSectionType.EncryptedTally, RecordSectionType.ContestDataRequests];
        RecordSectionType[] final = [RecordSectionType.DecryptedTally, RecordSectionType.ChallengedBallotDecryptions, RecordSectionType.ContestDataDecryptions, RecordSectionType.UncastNonceReleases];

        Require(setup, "setup");
        var phase = RecordPhase.Setup;
        if (sections.Any(x => x.Phase >= RecordPhase.Sealed))
        {
            Require([RecordSectionType.DeviceAttestations], "sealed (voting)");
            phase = RecordPhase.Sealed;
        }

        if (sections.Any(x => x.Phase >= RecordPhase.Aggregated))
        {
            Require(aggregated, "aggregated");
            phase = RecordPhase.Aggregated;
        }

        if (sections.Any(x => x.Phase >= RecordPhase.Final))
        {
            Require(final, "final");
            phase = RecordPhase.Final;
        }

        return phase;

        void Require(RecordSectionType[] required, string name)
        {
            var missing = required.Where(x => !types.Contains(x)).ToList();
            if (missing.Count > 0)
            {
                throw RecordCodes.Failure(RecordCodes.Structure, $"The record holds sections of the {name} phase or later, but not section(s) {string.Join(", ", missing.Select(x => $"0x{(ushort)x:x4}"))}, which that phase requires (§4.5).");
            }
        }
    }

    private async ValueTask ReadFormatAsync(CancellationToken ct)
    {
        // The header item fixes the minor every other item is checked at, so it is read first, as a
        // reader older than any minor would read it (unknown fields allowed by W6), and checked again
        // at the record's own minor whenever the header section is read.
        Pb.RecordItem? header = null;
        await foreach (var item in ReadSectionAsync(SectionKey.Of(RecordSectionType.Header), 0, ushort.MaxValue, ct).ConfigureAwait(false))
        {
            if (header is not null || !item.Check.IsCanonical)
            {
                throw RecordCodes.Failure(header is null ? RecordCodes.Encoding : RecordCodes.Structure, header is null
                    ? $"The header item is not canonical ({item.Check.Rule}): {item.Check.Message}"
                    : "The header section holds more than one item (§4.5).");
            }

            header = Pb.RecordItem.Parser.ParseFrom(item.Bytes.Span);
        }

        if (header?.ItemCase != Pb.RecordItem.ItemOneofCase.RecordHeader)
        {
            throw RecordCodes.Failure(RecordCodes.Structure, "The header section does not hold one record_header item (§4.5).");
        }

        if (header.RecordHeader.FormatMajor != RecordFormatVersion.Library.Major || header.RecordHeader.FormatMinor > ushort.MaxValue)
        {
            throw RecordCodes.Failure(RecordCodes.Version, $"The record is EGRF {header.RecordHeader.FormatMajor}.{header.RecordHeader.FormatMinor}; this reader reads major {RecordFormatVersion.Library.Major} (design §7).");
        }

        Format = new RecordFormatVersion((ushort)header.RecordHeader.FormatMajor, (ushort)header.RecordHeader.FormatMinor);
    }

    private async ValueTask ReadClaimedTocAsync(CancellationToken ct)
    {
        if (TocPath is null)
        {
            return;
        }

        var entries = new List<TocEntry>();
        await foreach (var item in ReadSegmentAsync(TocPath, new SectionKey((RecordSectionType)0xFFFE, []), 0, Format.Minor, ct).ConfigureAwait(false))
        {
            if (!item.Check.IsCanonical)
            {
                throw RecordCodes.Failure(RecordCodes.Encoding, $"TOC item {item.Ordinal} is not canonical ({item.Check.Rule}): {item.Check.Message}");
            }

            var parsed = Pb.RecordItem.Parser.ParseFrom(item.Bytes.Span);
            if (parsed.ItemCase != Pb.RecordItem.ItemOneofCase.TocEntry)
            {
                throw RecordCodes.Failure(RecordCodes.Root, $"TOC item {item.Ordinal} is not a toc_entry.");
            }

            var entry = parsed.TocEntry;
            if ((ushort)entry.SectionType is 0 or > RecordSections.LastVendorType || entry.ItemCount > long.MaxValue)
            {
                throw RecordCodes.Failure(RecordCodes.Root, $"TOC item {item.Ordinal} names section type {(int)entry.SectionType}, which no TOC holds.");
            }

            entries.Add(new TocEntry((RecordSectionType)(ushort)entry.SectionType, entry.Key.Span, entry.Critical, (long)entry.ItemCount, Sha256Digest.FromBytes(entry.Root.Span)));
        }

        try
        {
            ClaimedToc = new TableOfContents(entries);
        }
        catch (ArgumentException ex)
        {
            throw RecordCodes.Failure(RecordCodes.Root, $"The claimed table of contents is not one: {ex.Message}");
        }
    }

    public async ValueTask<RecordSetup> ReadSetupAsync(CancellationToken ct = default)
    {
        var items = await ReadSetupItemsAsync(ct).ConfigureAwait(false);
        var decoded = SetupMapper.FromItems(items);
        if (decoded.Findings.Count > 0)
        {
            var finding = decoded.Findings[0];
            throw new VerificationFailedException(finding.SubSection, finding.Message);
        }

        var setup = decoded.Value!;
        await CheckManifestCopyAsync(setup.ManifestFile.Bytes, ct).ConfigureAwait(false);
        return setup;
    }

    /// <summary>The setup items in canonical order, each canonical and of its section's member (<c>R.structure</c> otherwise).</summary>
    internal async ValueTask<List<Pb.RecordItem>> ReadSetupItemsAsync(CancellationToken ct)
    {
        var items = new List<Pb.RecordItem>();
        (RecordSectionType Type, Pb.RecordItem.ItemOneofCase Member, bool Many)[] sections =
        [
            (RecordSectionType.Header, Pb.RecordItem.ItemOneofCase.RecordHeader, false),
            (RecordSectionType.Parameters, Pb.RecordItem.ItemOneofCase.Parameters, false),
            (RecordSectionType.Manifest, Pb.RecordItem.ItemOneofCase.ManifestFile, false),
            (RecordSectionType.Guardians, Pb.RecordItem.ItemOneofCase.GuardianPublicKey, true),
            (RecordSectionType.ElectionKeys, Pb.RecordItem.ItemOneofCase.ElectionKeys, false),
        ];

        foreach (var (type, member, many) in sections)
        {
            int count = 0;
            await foreach (var item in ReadCanonicalAsync(SectionKey.Of(type), ct).ConfigureAwait(false))
            {
                var parsed = Pb.RecordItem.Parser.ParseFrom(item.Bytes.Span);
                if (parsed.ItemCase != member)
                {
                    throw RecordCodes.Failure(RecordCodes.Structure, $"Section 0x{(ushort)type:x4} holds item member {(int)parsed.ItemCase}; it holds {member} items only (§4.5).");
                }

                items.Add(parsed);
                count++;
            }

            if (many ? count == 0 : count != 1)
            {
                throw RecordCodes.Failure(RecordCodes.Structure, $"Section 0x{(ushort)type:x4} holds {count} items; it holds {(many ? "one or more" : "exactly one")} (§4.5).");
            }
        }

        return items;
    }

    /// <summary>A <c>setup/manifest.json</c> copy, when present, must be byte-identical to the stored manifest (§4.6; <c>R.container</c>).</summary>
    internal async ValueTask CheckManifestCopyAsync(ReadOnlyMemory<byte> manifest, CancellationToken ct)
    {
        if (ManifestCopyPath is null)
        {
            return;
        }

        // Compared as it streams, so a copy longer than the stored manifest (at most 64 MiB) is
        // refused at its first extra byte rather than read whole.
        await using var stream = _source.OpenRead(ManifestCopyPath);
        byte[] buffer = new byte[1 << 16];
        long compared = 0;
        int read;
        while ((read = await stream.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
        {
            if (read > manifest.Length - compared || !buffer.AsSpan(0, read).SequenceEqual(manifest.Span.Slice((int)compared, read)))
            {
                throw NotIdentical();
            }

            compared += read;
        }

        if (compared != manifest.Length)
        {
            throw NotIdentical();
        }

        Exception NotIdentical() => RecordCodes.Failure(RecordCodes.Container, $"{ManifestCopyPath} is not byte-identical to the manifest stored in the record (§4.6).");
    }

    public IDeviceSectionReader OpenDevice(DeviceKey device)
    {
        var key = SectionKey.Device(device);
        if (!_segments.ContainsKey(key))
        {
            throw new ArgumentException($"The record has no section for device {key}.", nameof(device));
        }

        return new DeviceReader(this, device);
    }

    public IAsyncEnumerable<RecordItemBytes> ReadSectionAsync(SectionKey section, long fromOrdinal = 0, CancellationToken ct = default) =>
        ReadSectionAsync(section, fromOrdinal, Format.Minor, ct);

    /// <summary>The items of <paramref name="section"/>, each canonical (<c>R.encoding</c> at the first that is not).</summary>
    internal async IAsyncEnumerable<RecordItemBytes> ReadCanonicalAsync(SectionKey section, [EnumeratorCancellation] CancellationToken ct)
    {
        await foreach (var item in ReadSectionAsync(section, 0, ct).ConfigureAwait(false))
        {
            if (!item.Check.IsCanonical)
            {
                throw RecordCodes.Failure(RecordCodes.Encoding, $"Item {item.Ordinal} of section {section} is not canonical ({item.Check.Rule}): {item.Check.Message}");
            }

            yield return item;
        }
    }

    private async IAsyncEnumerable<RecordItemBytes> ReadSectionAsync(SectionKey section, long fromOrdinal, ushort minor, [EnumeratorCancellation] CancellationToken ct)
    {
        if (!_segments.TryGetValue(section, out var paths))
        {
            throw new ArgumentException($"The record has no section {section}.", nameof(section));
        }

        long first = 0;
        foreach (var path in paths)
        {
            long next = first;
            await foreach (var item in ReadSegmentAsync(path, section, first, minor, ct).ConfigureAwait(false))
            {
                next = item.Ordinal + 1;
                if (item.Ordinal >= fromOrdinal)
                {
                    yield return item;
                }
            }

            first = next;
        }
    }

    public async IAsyncEnumerable<RecordItemBytes> ReadSignaturesAsync([EnumeratorCancellation] CancellationToken ct = default)
    {
        foreach (var path in _signatureFiles)
        {
            await foreach (var item in ReadSegmentAsync(path, new SectionKey((RecordSectionType)0xFFFF, []), 0, Format.Minor, ct).ConfigureAwait(false))
            {
                yield return item;
            }
        }
    }

    internal IReadOnlyList<string> SignatureFiles => _signatureFiles;

    /// <summary>The segment files of <paramref name="section"/>, in order.</summary>
    internal IReadOnlyList<string> SegmentPaths(SectionKey section) => _segments[section];

    /// <summary>
    /// One segment file: its header (D6, path agreement, first ordinal; <c>R.container</c>), then its
    /// items. Protobuf: frames, each length checked before allocation. JSON: lines, each parsed to its
    /// canonical bytes; a line that is not one item is <c>R.encoding</c>, one over the frame ceiling
    /// <c>R.container</c>, and the file must end with a line feed (a torn tail otherwise).
    /// </summary>
    internal async IAsyncEnumerable<RecordItemBytes> ReadSegmentAsync(string path, SectionKey section, long firstOrdinal, ushort minor, [EnumeratorCancellation] CancellationToken ct)
    {
        await using var raw = _source.OpenRead(path);
        await using var stream = new BufferedStream(raw, 1 << 16);
        var lines = Encoding == RecordEncoding.Json ? new LineReader(stream, path) : null;

        byte[] headerBytes = lines is null
            ? await SegmentFraming.ReadFrameAsync(stream, path, ct).ConfigureAwait(false) ?? throw RecordCodes.Failure(RecordCodes.Container, $"{path}: an empty file; a segment starts with its header (D6).")
            : ParseHeaderLine(await lines.NextAsync(ct).ConfigureAwait(false) ?? throw RecordCodes.Failure(RecordCodes.Container, $"{path}: an empty file; a segment starts with its header (D6)."), path, minor);
        var check = CanonicalProtobuf.CheckSegmentHeader(headerBytes, minor);
        if (!check.IsCanonical)
        {
            throw RecordCodes.Failure(RecordCodes.Container, $"{path}: {check.Message}");
        }

        var header = Pb.SegmentHeader.Parser.ParseFrom(headerBytes);
        if ((ushort)header.SectionType != (ushort)section.Type || !header.Key.Span.SequenceEqual(section.Key.Span))
        {
            throw RecordCodes.Failure(RecordCodes.Container, $"{path}: the segment header names section 0x{(int)header.SectionType:x4}/{Convert.ToHexStringLower(header.Key.Span)}, its path {section} (D6, §5.3.1: neither one wins).");
        }

        if (header.FirstOrdinal != (ulong)firstOrdinal)
        {
            throw RecordCodes.Failure(RecordCodes.Container, $"{path}: the segment's first ordinal is {header.FirstOrdinal}; the previous segments end at {firstOrdinal} (a gap or overlap, §5.2).");
        }

        long ordinal = firstOrdinal;
        while (true)
        {
            byte[]? bytes;
            if (lines is null)
            {
                bytes = await SegmentFraming.ReadFrameAsync(stream, path, ct).ConfigureAwait(false);
            }
            else
            {
                var line = await lines.NextAsync(ct).ConfigureAwait(false);
                bytes = line is null ? null : ParseItemLine(line, path, minor);
            }

            if (bytes is null)
            {
                yield break;
            }

            yield return new RecordItemBytes(bytes, ordinal++, CanonicalProtobuf.Check(bytes, minor));
        }
    }

    private static byte[] ParseHeaderLine(byte[] line, string path, ushort minor)
    {
        try
        {
            return RecordJson.ParseSegmentHeader(line, minor);
        }
        catch (VerificationFailedException ex)
        {
            throw RecordCodes.Failure(RecordCodes.Container, $"{path}: the segment header line: {ex.Message}");
        }
    }

    private static byte[] ParseItemLine(byte[] line, string path, ushort minor)
    {
        byte[] bytes;
        try
        {
            bytes = RecordJson.ParseItem(line, minor);
        }
        catch (VerificationFailedException ex)
        {
            throw new VerificationFailedException(ex.SubSection, $"{path}: {ex.Message}");
        }

        if (bytes.Length is 0 or > SegmentFraming.MaxFrameLength)
        {
            throw RecordCodes.Failure(bytes.Length == 0 ? RecordCodes.Encoding : RecordCodes.Container, $"{path}: a line whose canonical encoding is {bytes.Length} bytes; an item is 1 byte to 64 MiB (§5.2, §5.3.1).");
        }

        return bytes;
    }

    public ValueTask DisposeAsync()
    {
        _source.Dispose();
        return ValueTask.CompletedTask;
    }

    internal static DeviceKey DeviceKeyOf(ReadOnlySpan<byte> key) =>
        new(DeviceKey.KindOf(key[0]) ?? throw new ArgumentException("Not a device key.", nameof(key)), VotingDeviceInformationHash.FromCanonicalBytes(key[1..].ToArray()));

    /// <summary>
    /// Reads lines by design §5.5's line rules with a bounded buffer: every line ends with '\n' (a
    /// final line without it is a torn tail), one '\r' before it is removed, an empty line and a line
    /// over <see cref="RecordJson.MaxLineLength"/> bytes are refused; all <c>R.container</c>.
    /// </summary>
    internal sealed class LineReader(Stream stream, string path)
    {
        private readonly byte[] _buffer = new byte[1 << 16];
        private int _start;
        private int _end;

        public async ValueTask<byte[]?> NextAsync(CancellationToken ct)
        {
            MemoryStream? partial = null;
            while (true)
            {
                int newline = Array.IndexOf(_buffer, (byte)'\n', _start, _end - _start);
                if (newline >= 0)
                {
                    byte[] line;
                    if (partial is null)
                    {
                        line = _buffer.AsSpan(_start, newline - _start).ToArray();
                    }
                    else
                    {
                        partial.Write(_buffer, _start, newline - _start);
                        line = partial.ToArray();
                    }

                    _start = newline + 1;
                    if (line.Length > RecordJson.MaxLineLength)
                    {
                        throw TooLong();
                    }

                    int length = line.Length > 0 && line[^1] == (byte)'\r' ? line.Length - 1 : line.Length;
                    if (length == 0)
                    {
                        throw RecordCodes.Failure(RecordCodes.Container, $"{path}: an empty line, which is no item (§5.5).");
                    }

                    return length == line.Length ? line : line[..length];
                }

                if (_end > _start)
                {
                    partial ??= new MemoryStream();
                    partial.Write(_buffer, _start, _end - _start);
                    if (partial.Length > RecordJson.MaxLineLength)
                    {
                        throw TooLong();
                    }
                }

                _start = 0;
                _end = await stream.ReadAsync(_buffer, ct).ConfigureAwait(false);
                if (_end == 0)
                {
                    if (partial is { Length: > 0 })
                    {
                        throw RecordCodes.Failure(RecordCodes.Container, $"{path}: the file ends inside a line (a torn tail; every line ends with a line feed, §5.5).");
                    }

                    return null;
                }
            }
        }

        private Exception TooLong() =>
            RecordCodes.Failure(RecordCodes.Container, $"{path}: a line longer than {RecordJson.MaxLineLength} bytes (without its line feed), refused before parsing (§5.5).");
    }

    private sealed class DeviceReader(ElectionRecordReader reader, DeviceKey key) : IDeviceSectionReader
    {
        private SectionKey Section => SectionKey.Device(Key);

        public DeviceKey Key { get; } = key;

        private string StructureCode => Key.Kind == DeviceChainBallotKind.PreEncrypted ? "16.structure" : "8.structure";

        public async ValueTask<DeviceHeader> ReadHeaderAsync(CancellationToken ct = default)
        {
            await foreach (var item in reader.ReadCanonicalAsync(Section, ct).ConfigureAwait(false))
            {
                var parsed = Pb.RecordItem.Parser.ParseFrom(item.Bytes.Span);
                if (parsed.ItemCase != Pb.RecordItem.ItemOneofCase.DeviceHeader)
                {
                    throw new VerificationFailedException(StructureCode, $"Device section {Section}'s first item is member {(int)parsed.ItemCase}, not device_header (§4.5).");
                }

                var header = DeviceMapper.FromItem(parsed.DeviceHeader);
                if (header.Key != Key)
                {
                    throw new VerificationFailedException(StructureCode, $"Device section {Section}'s header names kind {header.Kind} and H_DI {header.DeviceInformationHash}, not the section's key (§4.5).");
                }

                return header;
            }

            throw new VerificationFailedException(StructureCode, $"Device section {Section} holds no item (§4.5: a device_header first).");
        }

        public async IAsyncEnumerable<RecordItemBytes> ReadEntriesAsync([EnumeratorCancellation] CancellationToken ct = default)
        {
            // One item of look-ahead: the last item is the close, not an entry.
            RecordItemBytes? pending = null;
            await foreach (var item in reader.ReadSectionAsync(Section, 1, ct).ConfigureAwait(false))
            {
                if (pending is { } previous)
                {
                    yield return previous;
                }

                pending = item;
            }

            if (pending is { } last && !(last.Check.IsCanonical && IsClose(last)))
            {
                yield return last;
            }
        }

        public async ValueTask<DeviceClose?> ReadCloseAsync(CancellationToken ct = default)
        {
            RecordItemBytes? last = null;
            await foreach (var item in reader.ReadSectionAsync(Section, 1, ct).ConfigureAwait(false))
            {
                last = item;
            }

            if (last is not { } close || !close.Check.IsCanonical || !IsClose(close))
            {
                return null;
            }

            return DeviceMapper.FromItem(Pb.RecordItem.Parser.ParseFrom(close.Bytes.Span).DeviceClose);
        }

        private static bool IsClose(RecordItemBytes item) =>
            Pb.RecordItem.Parser.ParseFrom(item.Bytes.Span).ItemCase == Pb.RecordItem.ItemOneofCase.DeviceClose;
    }
}
