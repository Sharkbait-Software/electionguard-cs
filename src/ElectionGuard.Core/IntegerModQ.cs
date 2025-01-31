using System.Numerics;

namespace ElectionGuard.Core;

/// <summary>
/// §3.1.1 Integer mod small prime q
/// </summary>
public class IntegerModQ
{
    public IntegerModQ(BigInteger i, BigInteger q)
    {
        _q = q;
        if (i > q || i < 0)
        {
            _i = i.Mod(q);
        }
        else
        {
            _i = i;
        }
    }

    public IntegerModQ(byte[] bytes, BigInteger q)
    {
        _q = q;
        _i = new BigInteger(bytes, true, true);
        if (_i > q || _i < 0)
        {
            _i = _i.Mod(q);
        }
    }

    private readonly BigInteger _i;
    private readonly BigInteger _q;

    public byte[] ToByteArray()
    {
        return _i.ToByteArray(true, true);
    }

    public BigInteger ToBigInteger()
    {
        return _i;
    }

    public static IntegerModQ Pow(IntegerModQ value, int exponent)
    {
        return new IntegerModQ(BigInteger.Pow(value, exponent), value._q);
    }

    public static IntegerModQ Pow(int value, int exponent, IntegerModQ q)
    {
        return new IntegerModQ(BigInteger.Pow(value, exponent), q);
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
        return new IntegerModQ(a._i + b._i, a._q);
    }

    public static IntegerModQ operator -(IntegerModQ a, IntegerModQ b)
    {
        return new IntegerModQ(a._i - b._i, a._q);
    }

    public static IntegerModQ operator *(IntegerModQ a, IntegerModQ b)
    {
        return new IntegerModQ(a._i * b._i, a._q);
    }
}