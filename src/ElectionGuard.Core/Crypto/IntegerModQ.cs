using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
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
        if (i >= EGParameters.CryptographicParameters.Q || i < 0)
        {
            _i = i.Mod(EGParameters.CryptographicParameters.Q);
        }
        else
        {
            _i = i;
        }
    }

    public IntegerModQ(byte[] bytes) : this(new BigInteger(bytes, true, true))
    {

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

    public static IntegerModQ operator +(IntegerModQ a, IntegerModQ b)
    {
        return new IntegerModQ(a._i + b._i);
    }

    public static IntegerModQ operator -(IntegerModQ a, IntegerModQ b)
    {
        return new IntegerModQ(a._i - b._i);
    }

    public static IntegerModQ operator *(IntegerModQ a, IntegerModQ b)
    {
        return new IntegerModQ(a._i * b._i);
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