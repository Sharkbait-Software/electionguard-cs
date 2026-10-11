namespace ElectionGuard.Core.RecordFormat;

/// <summary>
/// The length-delimited framing of <c>.binpb</c> segments (design §5.2): each frame is the minimal
/// varint of the message's length, then the message. A frame's length is at least 1 and at most
/// 64 MiB (<see cref="MaxFrameLength"/>), for the segment header and every item alike. The writer
/// refuses a larger item; the reader refuses a larger, zero or non-minimal length before it
/// allocates anything (<c>R.container</c>), so a hostile length varint cannot make it allocate up to
/// 2 GiB. A frame cut short is a torn tail, also <c>R.container</c> to a reader (a verifier never
/// repairs anything).
/// </summary>
internal static class SegmentFraming
{
    /// <summary>64 MiB: the largest frame (§5.2).</summary>
    public const int MaxFrameLength = 64 << 20;

    /// <summary>The varint of <paramref name="length"/>, written into <paramref name="destination"/>; returns its size.</summary>
    public static int WriteVarint(Span<byte> destination, ulong length)
    {
        int n = 0;
        while (length >= 0x80)
        {
            destination[n++] = (byte)(length | 0x80);
            length >>= 7;
        }

        destination[n++] = (byte)length;
        return n;
    }

    /// <summary>The size of a frame holding <paramref name="length"/> bytes.</summary>
    public static long FrameSize(int length)
    {
        Span<byte> varint = stackalloc byte[10];
        return WriteVarint(varint, (ulong)length) + length;
    }

    /// <summary>Throws <see cref="ArgumentException"/> unless 1 &lt;= <paramref name="length"/> &lt;= 64 MiB.</summary>
    public static void RequireFrameLength(long length, string what)
    {
        if (length < 1 || length > MaxFrameLength)
        {
            throw new ArgumentException($"{what} is {length} bytes; a frame holds 1 to {MaxFrameLength} bytes (64 MiB, design §5.2).");
        }
    }

    /// <summary>Writes one frame of <paramref name="message"/>.</summary>
    public static async ValueTask WriteFrameAsync(Stream stream, ReadOnlyMemory<byte> message, CancellationToken ct)
    {
        RequireFrameLength(message.Length, "The item");
        byte[] varint = new byte[10];
        int n = WriteVarint(varint, (ulong)message.Length);
        await stream.WriteAsync(varint.AsMemory(0, n), ct).ConfigureAwait(false);
        await stream.WriteAsync(message, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads the next frame of <paramref name="stream"/>: null at a clean end of the stream (between
    /// frames), else the message bytes. Throws <c>R.container</c> for a non-minimal, zero or
    /// oversized length, or a frame the stream ends inside (a torn tail).
    /// </summary>
    public static async ValueTask<byte[]?> ReadFrameAsync(Stream stream, string path, CancellationToken ct)
    {
        byte[] one = new byte[1];
        ulong length = 0;
        int shift = 0;
        int count = 0;
        while (true)
        {
            int read = await stream.ReadAsync(one, ct).ConfigureAwait(false);
            if (read == 0)
            {
                if (count == 0)
                {
                    return null;
                }

                throw RecordCodes.Failure(RecordCodes.Container, $"{path}: the file ends inside a frame's length (a torn tail, design §5.2).");
            }

            byte b = one[0];
            count++;
            // A minimal varint of at most 64 MiB (2^26) is at most 4 bytes, so a fifth byte means a
            // length over the ceiling or a non-minimal one; stopping here also keeps a 10-byte
            // varint from wrapping round to a small value.
            if (count > 4)
            {
                throw RecordCodes.Failure(RecordCodes.Container, $"{path}: a frame length varint of more than 4 bytes, so over the 64 MiB ceiling or not minimal (design §5.2).");
            }

            length |= (ulong)(b & 0x7F) << shift;
            shift += 7;
            if ((b & 0x80) == 0)
            {
                if (b == 0 && count > 1)
                {
                    throw RecordCodes.Failure(RecordCodes.Container, $"{path}: a frame length varint is not minimal (W4, design §5.2).");
                }

                break;
            }
        }

        if (length == 0)
        {
            throw RecordCodes.Failure(RecordCodes.Container, $"{path}: a zero-length frame, which is never written (design §5.2).");
        }

        if (length > MaxFrameLength)
        {
            throw RecordCodes.Failure(RecordCodes.Container, $"{path}: a frame of {length} bytes is over the 64 MiB ceiling (design §5.2).");
        }

        byte[] message = new byte[(int)length];
        int filled = 0;
        while (filled < message.Length)
        {
            int read = await stream.ReadAsync(message.AsMemory(filled), ct).ConfigureAwait(false);
            if (read == 0)
            {
                throw RecordCodes.Failure(RecordCodes.Container, $"{path}: the file ends {message.Length - filled} bytes inside a {message.Length}-byte frame (a torn tail, design §5.2).");
            }

            filled += read;
        }

        return message;
    }
}
