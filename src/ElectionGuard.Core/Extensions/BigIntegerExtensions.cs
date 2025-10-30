using System.Numerics;

namespace ElectionGuard.Core.Extensions;

public static class BigIntegerExtensions
{
    // Technically, the % operator is a remainder, not a modulo.
    // Therefore, it doesn't handle negative numbers correctly. This does.
    public static BigInteger Mod(this BigInteger a, BigInteger b)
    {
        BigInteger r = a % b;
        return r < 0 ? r + b : r;
    }

    public static BigInteger MathModPow(this BigInteger a, BigInteger exponent, BigInteger b)
    {
        var r = BigInteger.ModPow(a, exponent, b);
        return r < 0 ? r + b : r;
    }
}
