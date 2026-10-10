namespace ElectionGuard.Core.RecordFormat;

/// <summary>
/// The torn-tail repair of a resumed writer (design §5.2). A crash mid-append leaves at most one
/// torn trailing frame (protobuf: a length varint cut short or running past the end of the file;
/// JSON: a last line without its line feed), and some filesystems leave the file extended with zero
/// bytes, each of which would read as a zero-length frame. So a trailing run of zero bytes counts as
/// part of the torn tail, as do the first bytes of a length varint (which then reads as not minimal),
/// a whole length followed only by zeros, or a whole length and the first part of its frame followed
/// only by zeros (the frame ends in zeros and is not canonical). The scan cuts the file back to the
/// end of the last complete item. Anything else is not repaired: a frame or line that is not a
/// canonical item and is followed by anything but zeros, a zero-length frame, a length that is not
/// minimal (W4) or a frame of zeros followed by anything but zeros, or a frame over the ceiling
/// leaves the section unsealable until an operator decides (<see cref="InvalidDataException"/>). A
/// verifier never repairs anything. A zero-filled hole that happens to leave a canonical item (zeros
/// inside a bytes field, say) is not detectable here; a device that must not lose a ballot flushes
/// it to the disk (<see cref="DeviceSectionWriter.FlushAsync"/>) before it reports it recorded.
/// </summary>
internal static class SegmentRepair
{
    /// <summary>What a scan found: the header's size, the file's length after any cut, and how many bytes were cut.</summary>
    public readonly record struct Scan(long HeaderBytes, long Length, long CutBytes);

    /// <summary>
    /// Scans <paramref name="path"/>, calling <paramref name="onItem"/> with each complete item's
    /// canonical bytes in order. With <paramref name="repair"/> a torn tail is cut off the file;
    /// without, it is refused like corruption.
    /// </summary>
    public static async ValueTask<Scan> ScanAsync(string path, RecordEncoding encoding, ushort minor, bool repair, Func<byte[], ValueTask> onItem, CancellationToken ct)
    {
        long good;
        long header;
        await using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16, FileOptions.SequentialScan))
        {
            (header, good) = encoding == RecordEncoding.Protobuf
                ? await ScanFramesAsync(stream, path, minor, onItem, ct).ConfigureAwait(false)
                : await ScanLinesAsync(stream, path, minor, onItem, ct).ConfigureAwait(false);
        }

        long length = new FileInfo(path).Length;
        if (good < length)
        {
            if (!repair)
            {
                throw new InvalidDataException($"{path} has a torn tail of {length - good} bytes.");
            }

            await using var file = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None);
            file.SetLength(good);
            file.Flush(flushToDisk: true);
        }

        return new Scan(header, good, length - good);
    }

    private static async ValueTask<(long Header, long Good)> ScanFramesAsync(Stream stream, string path, ushort minor, Func<byte[], ValueTask> onItem, CancellationToken ct)
    {
        long length = stream.Length;
        var buffered = new BufferedStream(stream, 1 << 16);
        long position = 0;
        long header = -1;
        while (position < length)
        {
            long start = position;
            ulong size = 0;
            int shift = 0;
            int b;
            do
            {
                b = buffered.ReadByte();
                if (b < 0)
                {
                    return Torn(start);
                }

                position++;
                size |= (ulong)(b & 0x7F) << shift;
                shift += 7;
                if (shift > 28)
                {
                    throw Corrupt(path, start, "a frame length over the 64 MiB ceiling or not minimal");
                }
            }
            while ((b & 0x80) != 0);

            if (size == 0)
            {
                // A zero-filled tail is torn; a zero-length frame before anything else is corruption.
                return RestIsZeros(buffered) ? Torn(start) : throw Corrupt(path, start, "a zero-length frame followed by data");
            }

            if (b == 0 && position - start > 1)
            {
                // Not minimal (W4), which every reader refuses. The writer writes minimal lengths, so
                // this is the first bytes of a longer length followed by a zero-filled tail, which is
                // torn, or else corruption.
                return RestIsZeros(buffered) ? Torn(start) : throw Corrupt(path, start, "a frame length varint that is not minimal (W4)");
            }

            if (size > SegmentFraming.MaxFrameLength)
            {
                throw Corrupt(path, start, $"a frame of {size} bytes, over the 64 MiB ceiling");
            }

            if (position + (long)size > length)
            {
                return Torn(start);
            }

            byte[] item = new byte[(int)size];
            await buffered.ReadExactlyAsync(item, ct).ConfigureAwait(false);
            position += item.Length;
            if (!item.AsSpan().ContainsAnyExcept((byte)0))
            {
                // A length followed by zeros: no item is all zeros (field number 0 is never valid),
                // so if only zeros follow, the frame's bytes were never written (a zero-filled tail).
                return RestIsZeros(buffered) ? Torn(start) : throw Corrupt(path, start, "a frame of zero bytes followed by data");
            }

            var check = header < 0 ? CanonicalProtobuf.CheckSegmentHeader(item, minor) : CanonicalProtobuf.Check(item, minor);
            if (!check.IsCanonical)
            {
                // A frame whose first bytes reached the disk and whose later ones were zero-filled
                // (the file's new size committed, its last pages not): it ends in zeros, only zeros
                // follow it, and it is not canonical (a 0x00 tag is never valid). It is the torn
                // frame. A frame like it with anything after it is corruption.
                if (item[^1] == 0 && RestIsZeros(buffered))
                {
                    return Torn(start);
                }

                throw Corrupt(path, start, header < 0 ? "a segment header that is not canonical" : $"an item that is not canonical ({check.Rule}: {check.Message})");
            }

            if (header < 0)
            {
                header = position;
                continue;
            }

            await onItem(item).ConfigureAwait(false);
        }

        return (Math.Max(header, 0), position);

        (long, long) Torn(long at) => (Math.Max(header, 0), header < 0 ? 0 : at);
    }

    /// <summary>Reads <paramref name="stream"/> to its end; whether every byte left was zero.</summary>
    private static bool RestIsZeros(Stream stream)
    {
        int b;
        while ((b = stream.ReadByte()) >= 0)
        {
            if (b != 0)
            {
                return false;
            }
        }

        return true;
    }

    private static async ValueTask<(long Header, long Good)> ScanLinesAsync(Stream stream, string path, ushort minor, Func<byte[], ValueTask> onItem, CancellationToken ct)
    {
        var buffer = new byte[1 << 16];
        var line = new MemoryStream();
        long position = 0;
        long lineStart = 0;
        long header = -1;
        int read;
        while ((read = await stream.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
        {
            int from = 0;
            while (from < read)
            {
                int newline = Array.IndexOf(buffer, (byte)'\n', from, read - from);
                int end = newline < 0 ? read : newline;
                line.Write(buffer, from, end - from);
                if (line.Length > RecordJson.MaxLineLength)
                {
                    throw Corrupt(path, lineStart, "a line over the ceiling");
                }

                position += end - from;
                from = end;
                if (newline < 0)
                {
                    break;
                }

                position++;
                from++;
                byte[] text = line.ToArray();
                line.SetLength(0);
                try
                {
                    if (header < 0)
                    {
                        header = position;
                        if (!CanonicalProtobuf.CheckSegmentHeader(RecordJson.ParseSegmentHeader(text, minor), minor).IsCanonical)
                        {
                            throw Corrupt(path, lineStart, "a segment header that is not canonical");
                        }
                    }
                    else
                    {
                        await Item(RecordJson.ParseItem(text, minor), path, lineStart, minor, onItem).ConfigureAwait(false);
                    }
                }
                catch (Verify.VerificationFailedException ex)
                {
                    throw Corrupt(path, lineStart, ex.Message);
                }

                lineStart = position;
            }
        }

        // Whatever follows the last line feed (a partial line, or zeros) is the torn tail. A reader
        // accepts a last line without its line feed when it parses (§5.5, "Optional"), but this
        // library's writer ends every line, so here an unterminated line is one the crash stopped
        // before its line feed reached the disk: it was never flushed (DeviceSectionWriter.FlushAsync
        // writes whole lines), so no ballot that a device reported recorded is lost by cutting it.
        return (Math.Max(header, 0), header < 0 ? 0 : lineStart);
    }

    private static async ValueTask Item(byte[] item, string path, long at, ushort minor, Func<byte[], ValueTask> onItem)
    {
        var check = CanonicalProtobuf.Check(item, minor);
        if (!check.IsCanonical)
        {
            throw Corrupt(path, at, $"an item that is not canonical ({check.Rule}: {check.Message})");
        }

        await onItem(item).ConfigureAwait(false);
    }

    private static InvalidDataException Corrupt(string path, long at, string what) =>
        new($"{path} at byte {at}: {what}. This is not a torn tail; the section stays unsealable until an operator decides (design §5.2).");
}
