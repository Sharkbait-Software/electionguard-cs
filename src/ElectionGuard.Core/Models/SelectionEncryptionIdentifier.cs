using ElectionGuard.Core.Serialization;

namespace ElectionGuard.Core.Models;

/// <summary>
/// §3.3.2 the selection encryption identifier id_B, a 256-bit value drawn at random per ballot.
///
/// Equality is by content: Verification 5.A must find two ballots with the same id_B even when
/// their identifiers were read into separate arrays, which reference equality never would.
/// </summary>
public readonly struct SelectionEncryptionIdentifier : IEquatable<SelectionEncryptionIdentifier>
{
    /// <summary>The length of id_B in bytes: b(id_B, 32) in eq. (32).</summary>
    public const int ByteLength = 32;

    public SelectionEncryptionIdentifier(byte[] value)
    {
        _value = value;
    }

    /// <summary>
    /// Strict decoding for a published id_B: exactly <see cref="ByteLength"/> bytes, which eq. (32)
    /// hashes as b(id_B, 32). Throws <see cref="NonCanonicalEncodingException"/> otherwise.
    ///
    /// Takes a span, like <see cref="ElectionGuard.Core.Crypto.IntegerModP.FromCanonicalBytes"/> and
    /// <see cref="ElectionGuard.Core.Crypto.IntegerModQ.FromCanonicalBytes"/>: a field missing from a
    /// protobuf document decodes as a null array, which arrives here as an empty span and fails the
    /// length check, not as an <see cref="ArgumentNullException"/>. The bytes are copied.
    /// </summary>
    public static SelectionEncryptionIdentifier FromCanonicalBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != ByteLength)
        {
            throw new NonCanonicalEncodingException($"A selection encryption identifier must be exactly {ByteLength} bytes; got {bytes.Length}.");
        }

        return new SelectionEncryptionIdentifier(bytes.ToArray());
    }

    private readonly byte[] _value;

    private ReadOnlySpan<byte> Span => _value ?? [];

    public static implicit operator byte[](SelectionEncryptionIdentifier i)
    {
        return i._value;
    }

    public bool Equals(SelectionEncryptionIdentifier other)
    {
        return Span.SequenceEqual(other.Span);
    }

    public override bool Equals(object? obj)
    {
        return obj is SelectionEncryptionIdentifier other && Equals(other);
    }

    public override int GetHashCode()
    {
        // Every byte, through HashCode's per-process random seed: id_B is chosen by whoever produced
        // the ballot, so a hash of a fixed few bytes would let a crafted record collide every entry
        // of Verification 5.A's set.
        var hash = new HashCode();
        hash.AddBytes(Span);
        return hash.ToHashCode();
    }

    public static bool operator ==(SelectionEncryptionIdentifier a, SelectionEncryptionIdentifier b)
    {
        return a.Equals(b);
    }

    public static bool operator !=(SelectionEncryptionIdentifier a, SelectionEncryptionIdentifier b)
    {
        return !a.Equals(b);
    }

    public override string ToString()
    {
        return Convert.ToHexString(Span);
    }
}
