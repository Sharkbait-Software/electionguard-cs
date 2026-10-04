using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using System.Buffers;

namespace ElectionGuard.Core.Models;

/// <summary>
/// §4.1.1 Selection Hash. The hash ψ of one pre-encryption vector of a pre-encrypted ballot.
/// </summary>
public struct SelectionHash : IEquatable<SelectionHash>, IComparable<SelectionHash>
{
    public SelectionHash(byte[] bytes)
    {
        _value = bytes;
    }

    public SelectionHash(SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, IReadOnlyList<EncryptedValue> vector)
    {
        // Formulas (113)/(114): psi = H(HI; 0x40, alpha_1, beta_1, ..., alpha_m, beta_m), the same
        // for selection vectors and null vectors.
        int length = 1 + vector.Count * 2 * IntegerModP.ByteLength;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            Span<byte> message = buffer.AsSpan(0, length);
            message[0] = 0x40;
            int offset = 1;
            foreach (var encryption in vector)
            {
                encryption.Alpha.WriteBigEndian(message.Slice(offset, IntegerModP.ByteLength));
                offset += IntegerModP.ByteLength;
                encryption.Beta.WriteBigEndian(message.Slice(offset, IntegerModP.ByteLength));
                offset += IntegerModP.ByteLength;
            }

            _value = new byte[EGHash.HashBytes];
            EGHash.HashConcatenated(selectionEncryptionIdentifierHash, message, _value);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private readonly byte[] _value;

    public static implicit operator byte[](SelectionHash i)
    {
        return i._value;
    }

    /// <summary>
    /// §4.1.2: selection hashes are ordered as integers in big endian byte order. For equal-length
    /// arrays that is exactly an unsigned byte-by-byte comparison.
    /// </summary>
    public int CompareTo(SelectionHash other)
    {
        return _value.AsSpan().SequenceCompareTo(other._value);
    }

    public static bool operator ==(SelectionHash left, SelectionHash right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(SelectionHash left, SelectionHash right)
    {
        return !(left == right);
    }

    public override bool Equals(object? obj)
    {
        return obj is SelectionHash hash && Equals(hash);
    }

    public bool Equals(SelectionHash other)
    {
        return _value.SequenceEqual(other._value);
    }

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(_value);
        return hash.ToHashCode();
    }

    public override string ToString()
    {
        return Convert.ToHexString(_value);
    }
}
