using System.Buffers.Binary;
using System.Security.Cryptography;

namespace ElectionGuard.Core.RecordFormat;

/// <summary>
/// A SHA-256 digest, held inline (four 64-bit words, no array). The election record's digests,
/// Merkle nodes and roots are all of this type (design §4.9: bare SHA-256 with RFC 9162 framing,
/// never the spec's HMAC-keyed H). Equality is by value; <see cref="ToString"/> is lowercase hex.
/// </summary>
public readonly record struct Sha256Digest : IComparable<Sha256Digest>
{
    /// <summary>The digest width in bytes.</summary>
    public const int ByteLength = 32;

    private readonly ulong _a, _b, _c, _d;

    private Sha256Digest(ulong a, ulong b, ulong c, ulong d)
    {
        _a = a;
        _b = b;
        _c = c;
        _d = d;
    }

    /// <summary>A digest from exactly 32 bytes; throws <see cref="ArgumentException"/> on any other length.</summary>
    public static Sha256Digest FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != ByteLength)
        {
            throw new ArgumentException($"A SHA-256 digest is {ByteLength} bytes; got {bytes.Length}.", nameof(bytes));
        }

        return new Sha256Digest(
            BinaryPrimitives.ReadUInt64BigEndian(bytes),
            BinaryPrimitives.ReadUInt64BigEndian(bytes[8..]),
            BinaryPrimitives.ReadUInt64BigEndian(bytes[16..]),
            BinaryPrimitives.ReadUInt64BigEndian(bytes[24..]));
    }

    /// <summary>A digest from 64 hexadecimal digits (either case).</summary>
    public static Sha256Digest FromHex(string hex) => FromBytes(Convert.FromHexString(hex));

    /// <summary>SHA-256 of <paramref name="data"/>.</summary>
    public static Sha256Digest Of(ReadOnlySpan<byte> data)
    {
        Span<byte> digest = stackalloc byte[ByteLength];
        SHA256.HashData(data, digest);
        return FromBytes(digest);
    }

    /// <summary>Writes the 32 bytes into the start of <paramref name="destination"/>.</summary>
    public void CopyTo(Span<byte> destination)
    {
        BinaryPrimitives.WriteUInt64BigEndian(destination, _a);
        BinaryPrimitives.WriteUInt64BigEndian(destination[8..], _b);
        BinaryPrimitives.WriteUInt64BigEndian(destination[16..], _c);
        BinaryPrimitives.WriteUInt64BigEndian(destination[24..], _d);
    }

    /// <summary>The 32 bytes, in a new array.</summary>
    public byte[] ToArray()
    {
        var bytes = new byte[ByteLength];
        CopyTo(bytes);
        return bytes;
    }

    /// <summary>Byte-wise (big-endian, unsigned) order.</summary>
    public int CompareTo(Sha256Digest other)
    {
        int c = _a.CompareTo(other._a);
        if (c != 0)
        {
            return c;
        }

        c = _b.CompareTo(other._b);
        if (c != 0)
        {
            return c;
        }

        c = _c.CompareTo(other._c);
        return c != 0 ? c : _d.CompareTo(other._d);
    }

    /// <summary>Lowercase hexadecimal, 64 digits.</summary>
    public override string ToString() => Convert.ToHexStringLower(ToArray());
}
