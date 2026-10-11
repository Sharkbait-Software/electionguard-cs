using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace ElectionGuard.Core.RecordFormat;

/// <summary>
/// A record's files in a seekable <c>.zip</c> (design §5.4), read with this library's own parser of
/// the zip format (APPNOTE 6.3.x), because <see cref="ZipArchive"/> exposes neither the local headers
/// nor where they are, hides a second entry of the same name, and gives no seekable view of a STORED
/// entry. The central directory is authoritative for the set of entries; for every entry it reads,
/// the reader checks that the local header agrees with it (name, method and, unless the entry has a
/// data descriptor, CRC-32 and both sizes, ZIP64 extra fields taken into account), and the CRC-32
/// and size of the data it reads. Duplicate names, encrypted entries, methods other than STORED (0)
/// and DEFLATE (8), multi-disk archives and anything that does not parse are <c>R.container</c>.
/// So is anything on which mainstream readers could disagree about the entry set (§5.4, "zip
/// consistency"): the central directory must fill exactly the bytes from its offset to the (ZIP64)
/// end-of-central-directory record and hold exactly the stated number of entries, the entry counts
/// must agree, a ZIP64 record must sit just before its locator and agree with the 32-bit fields it
/// replaces, and the end-of-central-directory record must be the last one in the archive.
/// Directory entries carry nothing and are otherwise ignored, but they must be valid names (§5.3.1,
/// case folding included), empty, STORED, not encrypted, with an agreeing local header. A non-seekable input is spooled to a temporary file first
/// (user decision NQ-6), which this source deletes when disposed.
/// </summary>
internal sealed class ZipRecordSource : IRecordSource
{
    private const uint EndOfCentralDirectory = 0x06054b50;
    private const uint Zip64EndOfCentralDirectory = 0x06064b50;
    private const uint Zip64Locator = 0x07064b50;
    private const uint CentralHeader = 0x02014b50;
    private const uint LocalHeader = 0x04034b50;

    private readonly Stream _stream;
    private readonly object _lock = new();
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Entry> _directories = new(StringComparer.Ordinal);

    private sealed record Entry(string Name, ushort Flags, ushort Method, uint Crc, long CompressedSize, long Size, long LocalHeaderOffset);

    private ZipRecordSource(Stream stream)
    {
        _stream = stream;
        try
        {
            ReadCentralDirectory();
        }
        catch (Exception ex) when (ex is EndOfStreamException or ArgumentOutOfRangeException or OverflowException or IOException)
        {
            throw RecordCodes.Failure(RecordCodes.Container, $"The archive is not a zip this reader can parse: {ex.Message}");
        }

        Files = _entries.Keys.ToList();
    }

    public RecordCarrier Carrier => RecordCarrier.Zip;

    public IReadOnlyList<string> Files { get; }

    /// <summary>
    /// Opens a record in <paramref name="stream"/>. A stream that cannot seek is copied to a
    /// temporary file in <paramref name="spoolDirectory"/> (default: the system temporary directory)
    /// first, which costs disk equal to the archive (design §5.4).
    /// </summary>
    public static async ValueTask<ZipRecordSource> OpenAsync(Stream stream, string? spoolDirectory, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (stream.CanSeek)
        {
            try
            {
                return new ZipRecordSource(stream);
            }
            catch
            {
                // The source owns the stream; a refused archive must not stay open (or locked).
                await stream.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        string directory = spoolDirectory ?? Path.GetTempPath();
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, $"egrf-spool-{Guid.NewGuid():N}.zip");
        var spool = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 1 << 16, FileOptions.DeleteOnClose | FileOptions.Asynchronous);
        try
        {
            await stream.CopyToAsync(spool, 1 << 20, ct).ConfigureAwait(false);
            await stream.DisposeAsync().ConfigureAwait(false);
            spool.Position = 0;
            return new ZipRecordSource(spool);
        }
        catch
        {
            await spool.DisposeAsync().ConfigureAwait(false);
            await stream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public Stream OpenRead(string path)
    {
        if (!_entries.TryGetValue(path, out var entry))
        {
            throw new FileNotFoundException($"The archive has no entry {path}.", path);
        }

        long dataOffset;
        lock (_lock)
        {
            try
            {
                dataOffset = CheckLocalHeader(entry);
            }
            catch (Exception ex) when (ex is EndOfStreamException or ArgumentOutOfRangeException or OverflowException or IOException)
            {
                throw Failure($"entry {entry.Name}'s local header does not parse: {ex.Message}");
            }
        }

        Stream data = new EntryWindow(_stream, _lock, dataOffset, entry.CompressedSize);
        if (entry.Method == 8)
        {
            data = new DeflateStream(data, CompressionMode.Decompress);
        }

        return new CheckedEntryStream(data, entry.Name, entry.Size, entry.Crc);
    }

    public void Dispose() => _stream.Dispose();

    private void ReadCentralDirectory()
    {
        long length = _stream.Length;
        if (length < 22)
        {
            throw Failure("the archive is shorter than an end-of-central-directory record");
        }

        // The EOCD record is the last 22 bytes plus a comment of at most 65,535 bytes. It is found the
        // way the common readers find it (Python's zipfile among them): a record with no comment at
        // the very end, else the last signature in the tail, which must then end the file exactly.
        int tail = (int)Math.Min(length, 22 + 0xFFFF);
        byte[] buffer = ReadAt(length - tail, tail);
        int eocd = tail - 22;
        if (BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(eocd)) != EndOfCentralDirectory
            || BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(eocd + 20)) != 0)
        {
            eocd = -1;
            for (int i = tail - 4; i >= 0; i--)
            {
                if (BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(i)) == EndOfCentralDirectory)
                {
                    eocd = i;
                    break;
                }
            }

            if (eocd < 0)
            {
                throw Failure("no end-of-central-directory record");
            }

            if (eocd > tail - 22 || eocd + 22 + BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(eocd + 20)) != tail)
            {
                throw Failure("the last end-of-central-directory signature does not start a record that ends the archive (a signature inside the comment, or bytes after the comment)");
            }
        }

        var record = buffer.AsSpan(eocd);
        ushort disk = BinaryPrimitives.ReadUInt16LittleEndian(record[4..]);
        ushort cdDisk = BinaryPrimitives.ReadUInt16LittleEndian(record[6..]);
        long diskCount = BinaryPrimitives.ReadUInt16LittleEndian(record[8..]);
        long count = BinaryPrimitives.ReadUInt16LittleEndian(record[10..]);
        long cdSize = BinaryPrimitives.ReadUInt32LittleEndian(record[12..]);
        long cdOffset = BinaryPrimitives.ReadUInt32LittleEndian(record[16..]);
        long eocdOffset = length - tail + eocd;
        if (disk != 0 || cdDisk != 0)
        {
            throw Failure("a multi-disk archive");
        }

        if (diskCount != count)
        {
            throw Failure($"the end-of-central-directory record gives {diskCount} entries on this disk and {count} in all");
        }

        // Where the central directory must end: at the ZIP64 end-of-central-directory record when
        // there is one, else at the EOCD record. Like the common readers, a ZIP64 locator just before
        // the EOCD record is what makes an archive ZIP64, whatever the 32-bit fields say.
        long directoryEnd = eocdOffset;
        bool zip64Marked = count == 0xFFFF || cdSize == 0xFFFFFFFF || cdOffset == 0xFFFFFFFF;
        byte[]? locator = eocdOffset >= 20 ? ReadAt(eocdOffset - 20, 20) : null;
        if (locator is not null && BinaryPrimitives.ReadUInt32LittleEndian(locator) == Zip64Locator)
        {
            // The ZIP64 EOCD record (56 bytes, no extensible data) sits just before the locator,
            // which points at it, on disk 0 of 1.
            long zip64Offset = eocdOffset - 20 - 56;
            if (zip64Offset < 0
                || BinaryPrimitives.ReadUInt32LittleEndian(locator.AsSpan(4)) != 0
                || BinaryPrimitives.ReadUInt64LittleEndian(locator.AsSpan(8)) != (ulong)zip64Offset
                || BinaryPrimitives.ReadUInt32LittleEndian(locator.AsSpan(16)) != 1)
            {
                throw Failure("the ZIP64 end-of-central-directory locator does not point at the record just before it, on the one disk");
            }

            byte[] zip64 = ReadAt(zip64Offset, 56);
            if (BinaryPrimitives.ReadUInt32LittleEndian(zip64) != Zip64EndOfCentralDirectory
                || BinaryPrimitives.ReadUInt64LittleEndian(zip64.AsSpan(4)) != 44)
            {
                throw Failure("the ZIP64 end-of-central-directory record is not just before its locator, or carries extensible data");
            }

            if (BinaryPrimitives.ReadUInt32LittleEndian(zip64.AsSpan(16)) != 0 || BinaryPrimitives.ReadUInt32LittleEndian(zip64.AsSpan(20)) != 0)
            {
                throw Failure("a multi-disk archive (ZIP64)");
            }

            long count64 = checked((long)BinaryPrimitives.ReadUInt64LittleEndian(zip64.AsSpan(32)));
            long cdSize64 = checked((long)BinaryPrimitives.ReadUInt64LittleEndian(zip64.AsSpan(40)));
            long cdOffset64 = checked((long)BinaryPrimitives.ReadUInt64LittleEndian(zip64.AsSpan(48)));
            if ((long)BinaryPrimitives.ReadUInt64LittleEndian(zip64.AsSpan(24)) != count64)
            {
                throw Failure("the ZIP64 end-of-central-directory record gives different entry counts for this disk and in all");
            }

            // A 32-bit field is either the ZIP64 marker or the same value, so no reader can take another.
            if ((count != 0xFFFF && count != count64) || (cdSize != 0xFFFFFFFF && cdSize != cdSize64) || (cdOffset != 0xFFFFFFFF && cdOffset != cdOffset64))
            {
                throw Failure("the end-of-central-directory record and its ZIP64 record disagree");
            }

            count = count64;
            cdSize = cdSize64;
            cdOffset = cdOffset64;
            directoryEnd = zip64Offset;
        }
        else if (zip64Marked)
        {
            throw Failure("a ZIP64 archive without its end-of-central-directory locator");
        }

        // The central directory fills exactly the bytes before the (ZIP64) EOCD record, as the common
        // readers assume when they locate it, so they all see the same directory (design §5.4).
        if (cdOffset < 0 || cdSize < 0 || cdOffset > directoryEnd || cdSize != directoryEnd - cdOffset)
        {
            throw Failure($"the central directory ({cdSize} bytes at {cdOffset}) does not end where the end-of-central-directory record starts ({directoryEnd})");
        }

        // Read the central directory in bounded chunks, never all at once.
        long position = cdOffset;
        long end = cdOffset + cdSize;
        for (long i = 0; i < count; i++)
        {
            byte[] fixedPart = ReadAt(position, 46);
            if (BinaryPrimitives.ReadUInt32LittleEndian(fixedPart) != CentralHeader)
            {
                throw Failure($"central directory entry {i} has no signature");
            }

            ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(fixedPart.AsSpan(8));
            ushort method = BinaryPrimitives.ReadUInt16LittleEndian(fixedPart.AsSpan(10));
            uint crc = BinaryPrimitives.ReadUInt32LittleEndian(fixedPart.AsSpan(16));
            long compressed = BinaryPrimitives.ReadUInt32LittleEndian(fixedPart.AsSpan(20));
            long size = BinaryPrimitives.ReadUInt32LittleEndian(fixedPart.AsSpan(24));
            int nameLength = BinaryPrimitives.ReadUInt16LittleEndian(fixedPart.AsSpan(28));
            int extraLength = BinaryPrimitives.ReadUInt16LittleEndian(fixedPart.AsSpan(30));
            int commentLength = BinaryPrimitives.ReadUInt16LittleEndian(fixedPart.AsSpan(32));
            ushort startDisk = BinaryPrimitives.ReadUInt16LittleEndian(fixedPart.AsSpan(34));
            long localOffset = BinaryPrimitives.ReadUInt32LittleEndian(fixedPart.AsSpan(42));
            byte[] variable = ReadAt(position + 46, nameLength + extraLength);
            string name = DecodeName(variable.AsSpan(0, nameLength), flags);
            ApplyZip64(variable.AsSpan(nameLength, extraLength), ref size, ref compressed, ref localOffset, startDisk, name, local: false);
            position += 46 + nameLength + extraLength + commentLength;
            if (position > end)
            {
                throw Failure("the central directory runs past its stated size");
            }

            if (name.EndsWith('/'))
            {
                // A directory entry carries nothing and is otherwise ignored, but it is held to the
                // naming rules (§5.3.1) like a file, and it may not hide data: STORED, empty, not
                // encrypted, with a local header that agrees (every mainstream writer stores
                // directories this way).
                RecordLayout.RequireValidName(name[..^1]);
                if ((flags & 0x0001) != 0 || method != 0 || size != 0 || compressed != 0)
                {
                    throw Failure($"directory entry {name} is not an empty STORED entry (method {method}, {compressed}/{size} bytes, flags 0x{flags:x4})");
                }

                if (localOffset < 0 || localOffset >= cdOffset)
                {
                    throw Failure($"directory entry {name}'s local header is outside the archive's data");
                }

                var directory = new Entry(name, flags, method, crc, compressed, size, localOffset);
                if (!_directories.TryAdd(name, directory))
                {
                    throw Failure($"two entries are named {name}");
                }

                continue;
            }

            if ((flags & 0x0001) != 0)
            {
                throw Failure($"entry {name} is encrypted");
            }

            if (method is not (0 or 8))
            {
                throw Failure($"entry {name} uses compression method {method}; only STORED (0) and DEFLATE (8) are allowed");
            }

            if (method == 0 && compressed != size)
            {
                throw Failure($"STORED entry {name} has a compressed size {compressed} unlike its size {size}");
            }

            if (localOffset < 0 || localOffset >= cdOffset)
            {
                throw Failure($"entry {name}'s local header is outside the archive's data");
            }

            if (!_entries.TryAdd(name, new Entry(name, flags, method, crc, compressed, size, localOffset)))
            {
                throw Failure($"two entries are named {name}");
            }
        }

        // A reader that walks the directory by its size (Python's zipfile does) would see entries
        // past the stated count; one that walks by count would not. Both must see the same set.
        if (position != end)
        {
            throw Failure($"the central directory holds {end - position} bytes after its {count} stated entries");
        }

        // A directory's name may not collide with a file's under case folding (§5.3.1); files among
        // themselves are checked again by the layout. A directory entry's local header must agree too.
        RecordLayout.RequireNoCaseFoldCollision(_entries.Keys.Concat(_directories.Keys.Select(x => x[..^1])));
        foreach (var directory in _directories.Values)
        {
            CheckLocalHeader(directory);
        }
    }

    /// <summary>Checks <paramref name="entry"/>'s local header against the central directory; returns where its data starts.</summary>
    private long CheckLocalHeader(Entry entry)
    {
        byte[] header = ReadAt(entry.LocalHeaderOffset, 30);
        if (BinaryPrimitives.ReadUInt32LittleEndian(header) != LocalHeader)
        {
            throw Failure($"entry {entry.Name} has no local header where the central directory says");
        }

        ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(6));
        ushort method = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(8));
        uint crc = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(14));
        long compressed = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(18));
        long size = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(22));
        int nameLength = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(26));
        int extraLength = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(28));
        byte[] variable = ReadAt(entry.LocalHeaderOffset + 30, nameLength + extraLength);
        string name = DecodeName(variable.AsSpan(0, nameLength), flags);
        long unusedOffset = 0;
        ApplyZip64(variable.AsSpan(nameLength, extraLength), ref size, ref compressed, ref unusedOffset, 0, name, local: true);

        if (name != entry.Name)
        {
            throw Failure($"entry {entry.Name}'s local header names {name}");
        }

        if (method != entry.Method || (flags & 0x0001) != 0)
        {
            throw Failure($"entry {entry.Name}'s local header gives method {method}, the central directory {entry.Method}");
        }

        // With a data descriptor (bit 3) the local CRC and sizes may all be zero (design §5.4). The
        // descriptor is not read: the central directory's values govern, and the entry's data is
        // checked against them as it is read (CheckedEntryStream), so no reader sees other content.
        // Any other local values must equal the central ones.
        bool descriptor = (flags & 0x0008) != 0;
        if (!(descriptor && crc == 0 && compressed == 0 && size == 0)
            && (crc != entry.Crc || compressed != entry.CompressedSize || size != entry.Size))
        {
            throw Failure($"entry {entry.Name}'s local header (CRC {crc:x8}, {compressed}/{size} bytes) disagrees with the central directory (CRC {entry.Crc:x8}, {entry.CompressedSize}/{entry.Size} bytes)");
        }

        long dataOffset = entry.LocalHeaderOffset + 30 + nameLength + extraLength;
        if (entry.CompressedSize > _stream.Length - dataOffset)
        {
            throw Failure($"entry {entry.Name} runs past the end of the archive");
        }

        return dataOffset;
    }

    /// <summary>Reads the ZIP64 extended information extra field (0x0001), whose values replace those stored as 0xFFFFFFFF.</summary>
    private static void ApplyZip64(ReadOnlySpan<byte> extra, ref long size, ref long compressed, ref long offset, ushort startDisk, string name, bool local)
    {
        bool needSize = size == 0xFFFFFFFF, needCompressed = compressed == 0xFFFFFFFF, needOffset = !local && offset == 0xFFFFFFFF;
        if (!local && startDisk == 0xFFFF)
        {
            throw Failure($"entry {name} names a ZIP64 start disk");
        }

        while (extra.Length >= 4)
        {
            ushort id = BinaryPrimitives.ReadUInt16LittleEndian(extra);
            int dataLength = BinaryPrimitives.ReadUInt16LittleEndian(extra[2..]);
            if (4 + dataLength > extra.Length)
            {
                throw Failure($"entry {name} has an extra field that runs past its extra data");
            }

            var data = extra.Slice(4, dataLength);
            if (id == 0x0001)
            {
                int at = 0;
                if (local)
                {
                    // A local ZIP64 field carries both sizes whenever either is 0xFFFFFFFF.
                    if (needSize || needCompressed)
                    {
                        if (data.Length < 16)
                        {
                            throw Failure($"entry {name}'s local ZIP64 field is short");
                        }

                        size = checked((long)BinaryPrimitives.ReadUInt64LittleEndian(data));
                        compressed = checked((long)BinaryPrimitives.ReadUInt64LittleEndian(data[8..]));
                        needSize = needCompressed = false;
                    }
                }
                else
                {
                    if (data.Length < 8 * ((needSize ? 1 : 0) + (needCompressed ? 1 : 0) + (needOffset ? 1 : 0)))
                    {
                        throw Failure($"entry {name}'s ZIP64 field is short");
                    }

                    if (needSize)
                    {
                        size = checked((long)BinaryPrimitives.ReadUInt64LittleEndian(data[at..]));
                        at += 8;
                        needSize = false;
                    }

                    if (needCompressed)
                    {
                        compressed = checked((long)BinaryPrimitives.ReadUInt64LittleEndian(data[at..]));
                        at += 8;
                        needCompressed = false;
                    }

                    if (needOffset)
                    {
                        offset = checked((long)BinaryPrimitives.ReadUInt64LittleEndian(data[at..]));
                        needOffset = false;
                    }
                }
            }

            extra = extra[(4 + dataLength)..];
        }

        if (needSize || needCompressed || needOffset)
        {
            throw Failure($"entry {name} marks a value as ZIP64 but has no ZIP64 extra field for it");
        }
    }

    private static string DecodeName(ReadOnlySpan<byte> bytes, ushort flags)
    {
        // Every name of a record, derived/ included, is printable ASCII (§5.3.1). Without the UTF-8
        // flag (bit 11) other bytes would be CP437, with it UTF-8; either way the name is refused
        // here, before it is decoded, rather than guessed at.
        foreach (byte b in bytes)
        {
            if (b is < 0x20 or > 0x7E)
            {
                throw Failure($"an entry name has the byte 0x{b:x2}; every name of a record is printable ASCII (§5.3.1; flags 0x{flags:x4})");
            }
        }

        return Encoding.ASCII.GetString(bytes);
    }

    private byte[] ReadAt(long offset, int count)
    {
        if (offset < 0 || count < 0 || offset > _stream.Length - count)
        {
            throw new EndOfStreamException($"{count} bytes at offset {offset} are outside the archive.");
        }

        byte[] buffer = new byte[count];
        _stream.Position = offset;
        _stream.ReadExactly(buffer);
        return buffer;
    }

    private static Exception Failure(string message) => RecordCodes.Failure(RecordCodes.Container, $"Zip: {message} (design §5.4).");

    /// <summary>A read-only window of the archive stream; reads take the archive's lock, so several windows can be read at once.</summary>
    private sealed class EntryWindow(Stream archive, object gate, long start, long length) : Stream
    {
        private long _position;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => length;

        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            long remaining = length - _position;
            if (remaining <= 0)
            {
                return 0;
            }

            int toRead = (int)Math.Min(buffer.Length, remaining);
            int read;
            lock (gate)
            {
                archive.Position = start + _position;
                read = archive.Read(buffer[..toRead]);
            }

            if (read == 0)
            {
                // The local header check bounds every entry inside the archive, so only an archive
                // that shrank while open gets here.
                throw Failure("the archive ends inside an entry");
            }

            _position += read;
            return read;
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>Counts and CRC-32s an entry's data as it is read; at its end, a size or CRC unlike the central directory's is <c>R.container</c>.</summary>
    private sealed class CheckedEntryStream(Stream inner, string name, long size, uint crc) : Stream
    {
        private uint _crc = 0xFFFFFFFF;
        private long _read;
        private bool _checked;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => size;

        public override long Position
        {
            get => _read;
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            int read;
            try
            {
                read = inner.Read(buffer);
            }
            catch (InvalidDataException ex)
            {
                throw Failure($"entry {name} does not inflate: {ex.Message}");
            }

            if (read > 0)
            {
                _crc = Crc32.Update(_crc, buffer[..read]);
                _read += read;
                if (_read > size)
                {
                    throw Failure($"entry {name} holds more than its {size} bytes");
                }
            }
            else if (!_checked)
            {
                _checked = true;
                if (_read != size || ~_crc != crc)
                {
                    throw Failure($"entry {name}'s data ({_read} bytes, CRC {~_crc:x8}) is not what the central directory states ({size} bytes, CRC {crc:x8})");
                }
            }

            return read;
        }

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

/// <summary>CRC-32 (ISO-HDLC, the zip polynomial 0xEDB88320, reflected), table driven.</summary>
internal static class Crc32
{
    private static readonly uint[] Table = Enumerable.Range(0, 256).Select(n =>
    {
        uint c = (uint)n;
        for (int k = 0; k < 8; k++)
        {
            c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
        }

        return c;
    }).ToArray();

    /// <summary>Continues a CRC register (start at 0xFFFFFFFF; the CRC is the complement of the final register).</summary>
    public static uint Update(uint register, ReadOnlySpan<byte> data)
    {
        foreach (byte b in data)
        {
            register = Table[(register ^ b) & 0xFF] ^ (register >> 8);
        }

        return register;
    }

    public static uint Compute(ReadOnlySpan<byte> data) => ~Update(0xFFFFFFFF, data);
}
