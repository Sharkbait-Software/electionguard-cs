using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using System.Diagnostics;
using System.Numerics;

namespace ElectionGuard.Core.Crypto;

/// <summary>
/// §3.1.1 Integer mod small prime q
/// </summary>
[DebuggerDisplay("{_i}")]
public struct IntegerModQ : IEquatable<IntegerModQ>
{
    public IntegerModQ(BigInteger i)
    {
        if (i >= EGParameters.Q || i < 0)
        {
            _i = i.Mod(EGParameters.Q);
        }
        else
        {
            _i = i;
        }
    }

    /// <summary>
    /// Reduces the big-endian value of <paramref name="bytes"/>, of any length, mod q. For internal
    /// arithmetic only: anything read from a record or ballot goes through
    /// <see cref="FromCanonicalBytes"/>, which rejects what this would silently reduce.
    /// </summary>
    public IntegerModQ(byte[] bytes) : this(new BigInteger(bytes, true, true))
    {

    }

    /// <summary>
    /// Strict decoding for published values (§5.1.2): exactly 32 big-endian bytes whose value is
    /// below q. Throws <see cref="NonCanonicalEncodingException"/> otherwise, where the reducing
    /// constructor would accept, say, a challenge c + q as c. This is what keeps the Z_q-range
    /// halves of Verifications 2.B, 6.B/6.C and 7.B/7.C meaningful for decoded records.
    /// </summary>
    public static IntegerModQ FromCanonicalBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != ByteLength)
        {
            throw new NonCanonicalEncodingException($"An element of Z_q must be encoded in exactly {ByteLength} bytes; got {bytes.Length}.");
        }

        var value = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        if (value >= EGParameters.Q)
        {
            throw new NonCanonicalEncodingException("An encoded element of Z_q is not below q.");
        }

        return new IntegerModQ(value);
    }

    private readonly BigInteger _i;

    public byte[] ToByteArray()
    {
        byte[] bytes = _i.ToByteArray(true, true);

        if (bytes.Length < 32)
        {
            bytes = bytes.PadToLength(32);
        }

        if (bytes.Length > 32)
        {
            throw new Exception($"Biginteger mod q too big! Length: {bytes.Length}");
        }

        return bytes;
    }

    /// <summary>The fixed width, in bytes, of <see cref="ToByteArray"/>'s output.</summary>
    internal const int ByteLength = 32;

    /// <summary>
    /// Writes the same 32 bytes as <see cref="ToByteArray"/> into the first 32 bytes of
    /// <paramref name="destination"/>, without allocating.
    /// </summary>
    internal void WriteBigEndian(Span<byte> destination)
    {
        _i.WriteBigEndianPadded(destination[..ByteLength]);
    }

    public BigInteger ToBigInteger()
    {
        return _i;
    }

    public static IntegerModQ PowModQ(IntegerModQ value, int exponent)
    {
        return new IntegerModQ(BigInteger.Pow(value, exponent));
    }

    public static IntegerModQ PowModQ(int value, int exponent)
    {
        return new IntegerModQ(BigInteger.Pow(value, exponent));
    }

    public static implicit operator byte[](IntegerModQ i)
    {
        return i.ToByteArray();
    }

    public static implicit operator BigInteger(IntegerModQ i)
    {
        return i.ToBigInteger();
    }

    public static implicit operator IntegerModQ(int i)
    {
        return new IntegerModQ(i);
    }

    public static IntegerModQ operator +(IntegerModQ a, IntegerModQ b)
    {
        return new IntegerModQ(a._i + b._i);
    }

    //public static IntegerModQ operator +(IntegerModQ a, int b)
    //{
    //    return new IntegerModQ(a._i + b);
    //}

    public static IntegerModQ operator -(IntegerModQ a, IntegerModQ b)
    {
        return new IntegerModQ(a._i - b._i);
    }

    //public static IntegerModQ operator -(IntegerModQ a, int b)
    //{
    //    return new IntegerModQ(a._i - b);
    //}

    public static IntegerModQ operator *(IntegerModQ a, IntegerModQ b)
    {
        return new IntegerModQ(a._i * b._i);
    }

    public static IntegerModQ operator /(IntegerModQ a, IntegerModQ b)
    {
        return new IntegerModQ(a._i * b._i.MathModPow(EGParameters.Q - 2, EGParameters.Q));
    }

    //public static IntegerModQ operator *(IntegerModQ a, int b)
    //{
    //    return new IntegerModQ(a._i * b);
    //}

    //public static IntegerModQ operator *(int a, IntegerModQ b)
    //{
    //    return new IntegerModQ(a * b._i);
    //}

    public static bool operator <(IntegerModQ a, IntegerModQ b)
    {
        return a._i < b._i;
    }

    public static bool operator >(IntegerModQ a, IntegerModQ b)
    {
        return a._i > b._i;
    }

    public static bool operator <=(IntegerModQ a, IntegerModQ b)
    {
        return a._i <= b._i;
    }

    public static bool operator >=(IntegerModQ a, IntegerModQ b)
    {
        return a._i >= b._i;
    }

    public override bool Equals(object? obj)
    {
        if (obj is IntegerModQ i)
        {
            return Equals(i);
        }

        return false;
    }

    public override int GetHashCode()
    {
        return _i.GetHashCode();
    }

    public bool Equals(IntegerModQ other)
    {
        return _i == other._i;
    }

    public static bool operator ==(IntegerModQ a, IntegerModQ b)
    {
        return a.Equals(b);
    }

    public static bool operator !=(IntegerModQ a, IntegerModQ b)
    {
        return !a.Equals(b);
    }
}