using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using System.Diagnostics;
using System.Numerics;

namespace ElectionGuard.Core.Crypto;

/// <summary>
/// §3.1.1 Integer mod large prime p
/// </summary>
[DebuggerDisplay("{_i}")]
public struct IntegerModP : IEquatable<IntegerModP>
{
    public IntegerModP(BigInteger i)
    {
        if (i >= EGParameters.CryptographicParameters.P || i < 0)
        {
            _i = i.Mod(EGParameters.CryptographicParameters.P);
        }
        else
        {
            _i = i;
        }
    }

    public IntegerModP(byte[] bytes) : this(new BigInteger(bytes, true, true))
    {

    }

    private readonly BigInteger _i;

    public byte[] ToByteArray()
    {
        byte[] bytes = _i.ToByteArray(true, true);

        if (bytes.Length < 512)
        {
            bytes = bytes.PadToLength(512);
        }

        if (bytes.Length > 512)
        {
            throw new Exception($"Biginteger mod p too big! Length: {bytes.Length}");
        }

        return bytes;
    }

    public BigInteger ToBigInteger()
    {
        return _i;
    }

    public static IntegerModP PowModP(IntegerModP value, IntegerModQ exponent)
    {
        return PowModP((BigInteger)value, exponent);
    }

    public static IntegerModP PowModP(BigInteger value, IntegerModQ exponent)
    {
        return PowModP(value, (BigInteger)exponent);
    }

    public static IntegerModP PowModP(BigInteger value, BigInteger exponent)
    {
        BigInteger result = BigInteger.ModPow(value, exponent, EGParameters.CryptographicParameters.P);
        return new IntegerModP(result);
    }

    public static implicit operator byte[](IntegerModP i)
    {
        return i.ToByteArray();
    }

    public static implicit operator BigInteger(IntegerModP i)
    {
        return i.ToBigInteger();
    }

    public static IntegerModP operator +(IntegerModP a, IntegerModP b)
    {
        return new IntegerModP(a._i + b._i);
    }

    public static IntegerModP operator -(IntegerModP a, IntegerModP b)
    {
        return new IntegerModP(a._i - b._i);
    }

    public static IntegerModP operator *(IntegerModP a, IntegerModP b)
    {
        return new IntegerModP(a._i * b._i);
    }

    public static IntegerModP operator /(IntegerModP a, IntegerModP b)
    {
        return new IntegerModP(a._i * PowModP(b, EGParameters.CryptographicParameters.P - 2)._i);
    }

    public override bool Equals(object? obj)
    {
        if (obj is IntegerModP i)
        {
            return Equals(i);
        }

        return false;
    }

    public override int GetHashCode()
    {
        return _i.GetHashCode();
    }

    public bool Equals(IntegerModP other)
    {
        return _i == other._i;
    }

    public static bool operator ==(IntegerModP a, IntegerModP b)
    {
        return a.Equals(b);
    }

    public static bool operator !=(IntegerModP a, IntegerModP b)
    {
        return !a.Equals(b);
    }
}
