using System.Numerics;
using System.Security.Cryptography;

namespace ElectionGuard.Core;

/// <summary>
/// §3.1.1 Integer mod large prime p
/// </summary>
public class IntegerModP
{
    public IntegerModP(BigInteger i, BigInteger p)
    {
        _p = p;
        if (i > p || i < 0)
        {
            _i = i.Mod(p);
        }
        else
        {
            _i = i;
        }
    }

    private readonly BigInteger _i;
    private readonly BigInteger _p;

    public byte[] ToByteArray()
    {
        return _i.ToByteArray(true, true);
    }

    public BigInteger ToBigInteger()
    {
        return _i;
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
        return new IntegerModP(a._i + b._i, a._p);
    }

    public static IntegerModP operator -(IntegerModP a, IntegerModP b)
    {
        return new IntegerModP(a._i - b._i, a._p);
    }

    public static IntegerModP operator *(IntegerModP a, IntegerModP b)
    {
        return new IntegerModP(a._i * b._i, a._p);
    }

    public static IntegerModP PowModP(IntegerModP value, IntegerModQ exponent)
    {
        BigInteger result = BigInteger.ModPow(value, exponent, value._p);
        return new IntegerModP(result, value._p);
    }
}
