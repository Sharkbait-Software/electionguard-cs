using ElectionGuard.Core.RecordFormat.Protobuf;
using Google.Protobuf;

namespace ElectionGuard.Core.RecordFormat;

/// <summary>
/// Writes one section as segment files (design §5.2, §5.3.1), streaming: each canonical item is
/// framed (protobuf) or projected to one JSON line, appended to the open segment, and folded into
/// the section's <see cref="MerkleFrontier"/>; nothing of an item is kept after it is written. Every
/// segment starts with its <c>SegmentHeader</c> (magic "EGRF", major 2, the section's type and key,
/// the ordinal of its first item). A section the layout shows as one file stays one segment; any
/// other rolls over to the next segment, at an item boundary, once a segment would pass
/// <see cref="SegmentSize"/> bytes (roots do not depend on where it splits). A section with no item
/// is still one segment holding the header alone, so it is present (§4.5).
/// </summary>
internal sealed class SectionWriter : IAsyncDisposable
{
    private readonly IRecordSink _sink;
    private readonly RecordEncoding _encoding;
    private readonly MerkleFrontier _frontier;
    private Stream? _segment;
    private int _segmentIndex = -1;
    private long _segmentBytes;
    private bool _completed;
    private bool _faulted;

    public SectionWriter(IRecordSink sink, SectionKey section, RecordEncoding encoding, long segmentSize)
    {
        _sink = sink;
        Section = section;
        _encoding = encoding;
        SegmentSize = segmentSize;
        _frontier = new MerkleFrontier();
    }

    /// <summary>
    /// A writer that continues a section already on disk (a resumed writer, design §5.2): its last
    /// segment, <paramref name="segmentIndex"/>, holds <paramref name="segmentBytes"/> bytes (after
    /// any torn tail was cut), and <paramref name="frontier"/> covers its <paramref name="count"/> items.
    /// </summary>
    public SectionWriter(DirectoryRecordSink sink, SectionKey section, RecordEncoding encoding, long segmentSize, int segmentIndex, long headerBytes, long segmentBytes, MerkleFrontier frontier, long count)
        : this(sink, section, encoding, segmentSize)
    {
        _frontier = frontier;
        Count = count;
        _segmentIndex = segmentIndex;
        _segmentBytes = segmentBytes;
        HeaderBytes = headerBytes;
        _segment = sink.Append(RecordLayout.SegmentPath(section, segmentIndex, encoding));
    }

    public SectionKey Section { get; }

    /// <summary>The size at which a segment rolls over (not canonical; default 256 MiB, design §5.2).</summary>
    public long SegmentSize { get; }

    /// <summary>The number of items written.</summary>
    public long Count { get; private set; }

    /// <summary>The section root over the items written so far.</summary>
    public Sha256Digest Root => _frontier.Root();

    /// <summary>
    /// Appends one item. <paramref name="item"/> must be canonical bytes (the writers produce them
    /// with the generated code; a copy passes the reader's checked bytes). Throws
    /// <see cref="ArgumentException"/> for an item over the 64 MiB frame ceiling, and <c>R.version</c>
    /// for content the JSON projection cannot carry; both before anything is written, so the section
    /// is as it was. A failure while writing (an I/O error) leaves the segment's tail unknown, so the
    /// section then refuses every later append (<see cref="InvalidOperationException"/>); resuming
    /// the writer repairs it (design §5.2).
    /// </summary>
    public async ValueTask AppendAsync(ReadOnlyMemory<byte> item, CanonicalCheck check, CancellationToken ct)
    {
        if (_completed)
        {
            throw new InvalidOperationException($"Section {Section} is complete.");
        }

        RequireNotFaulted();
        SegmentFraming.RequireFrameLength(item.Length, $"An item of section {Section}");
        ReadOnlyMemory<byte> stored = _encoding == RecordEncoding.Protobuf ? item : RecordJson.FormatItem(item.Span, check);
        long size = _encoding == RecordEncoding.Protobuf ? SegmentFraming.FrameSize(item.Length) : stored.Length + 1;
        try
        {
            if (_segment is null)
            {
                await OpenSegmentAsync(ct).ConfigureAwait(false);
            }
            else if (!RecordLayout.IsSingleFile(Section.Type) && _segmentBytes + size > SegmentSize && _segmentBytes > HeaderBytes)
            {
                await CloseSegmentAsync(durable: true).ConfigureAwait(false);
                await OpenSegmentAsync(ct).ConfigureAwait(false);
            }

            if (_encoding == RecordEncoding.Protobuf)
            {
                await SegmentFraming.WriteFrameAsync(_segment!, stored, ct).ConfigureAwait(false);
            }
            else
            {
                await _segment!.WriteAsync(stored, ct).ConfigureAwait(false);
                _segment.WriteByte((byte)'\n');
            }
        }
        catch
        {
            _faulted = true;
            throw;
        }

        _segmentBytes += size;
        _frontier.Append(item.Span);
        Count++;
    }

    /// <summary>Appends an item given as a generated message (its canonical encoding).</summary>
    public ValueTask AppendAsync(RecordItem item, CancellationToken ct) => AppendAsync(item.ToByteArray(), default, ct);

    /// <summary>Flushes the open segment; <paramref name="durable"/> also flushes the operating system's buffers.</summary>
    public async ValueTask FlushAsync(bool durable, CancellationToken ct)
    {
        if (_segment is null)
        {
            return;
        }

        await _segment.FlushAsync(ct).ConfigureAwait(false);
        if (durable && _segment is FileStream file)
        {
            file.Flush(flushToDisk: true);
        }
    }

    /// <summary>Closes the section and returns its TOC entry (the critical bit of §4.5 for its type, else <paramref name="critical"/>).</summary>
    public async ValueTask<TocEntry> CompleteAsync(bool critical, CancellationToken ct)
    {
        RequireNotFaulted();
        if (_segment is null && !_completed)
        {
            await OpenSegmentAsync(ct).ConfigureAwait(false);
        }

        await CloseSegmentAsync(durable: true).ConfigureAwait(false);
        _completed = true;
        return new TocEntry(Section.Type, Section.Key.Span, RecordSections.FixedCritical(Section.Type) ?? critical, Count, Root);
    }

    public async ValueTask DisposeAsync() => await CloseSegmentAsync(durable: false).ConfigureAwait(false);

    private long HeaderBytes { get; set; }

    private void RequireNotFaulted()
    {
        if (_faulted)
        {
            throw new InvalidOperationException($"Section {Section} failed while an item was being written, so its tail is unknown; resume the writer to repair it (design §5.2).");
        }
    }

    private async ValueTask OpenSegmentAsync(CancellationToken ct)
    {
        _segmentIndex++;
        string path = RecordLayout.SegmentPath(Section, _segmentIndex, _encoding);
        _segment = _sink.Create(path, compressible: _encoding == RecordEncoding.Json);
        var header = new SegmentHeader
        {
            Magic = "EGRF",
            FormatMajor = RecordFormatVersion.Library.Major,
            SectionType = (SectionType)(ushort)Section.Type,
            Key = ByteString.CopyFrom(Section.Key.Span),
            FirstOrdinal = (ulong)Count,
        };

        if (_encoding == RecordEncoding.Protobuf)
        {
            byte[] bytes = header.ToByteArray();
            await SegmentFraming.WriteFrameAsync(_segment, bytes, ct).ConfigureAwait(false);
            HeaderBytes = SegmentFraming.FrameSize(bytes.Length);
        }
        else
        {
            byte[] line = RecordJson.FormatSegmentHeader(header);
            await _segment.WriteAsync(line, ct).ConfigureAwait(false);
            _segment.WriteByte((byte)'\n');
            HeaderBytes = line.Length + 1;
        }

        _segmentBytes = HeaderBytes;
    }

    /// <summary>
    /// Closes the open segment. <paramref name="durable"/> (a rollover, or the section's completion)
    /// first flushes a file segment to the disk, so a segment a TOC will list, and so a phase root
    /// the writer hands back, survives a power failure (design §5.2). A zip entry is not flushed: a
    /// zip is written whole and is complete only once the archive is closed.
    /// </summary>
    private async ValueTask CloseSegmentAsync(bool durable)
    {
        if (_segment is not null)
        {
            var segment = _segment;
            _segment = null;
            try
            {
                if (durable && segment is FileStream file)
                {
                    file.Flush(flushToDisk: true);
                }
            }
            finally
            {
                await segment.DisposeAsync().ConfigureAwait(false);
            }
        }
    }
}
