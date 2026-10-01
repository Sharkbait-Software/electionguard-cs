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

    /// <summary>
    /// Writes a non-negative value as unsigned big-endian bytes filling the whole of
    /// <paramref name="destination"/>, zero-padded on the left: the bytes of
    /// <c>ToByteArray(isUnsigned: true, isBigEndian: true)</c> left-padded to the destination's
    /// length, without allocating either array. Throws when the value is wider than the destination,
    /// as IntegerModP/IntegerModQ.ToByteArray do.
    /// </summary>
    internal static void WriteBigEndianPadded(this BigInteger value, Span<byte> destination)
    {
        int count = value.GetByteCount(isUnsigned: true);
        if (count > destination.Length)
        {
            throw new Exception($"BigInteger too big for a {destination.Length}-byte field! Length: {count}");
        }

        int padding = destination.Length - count;
        destination[..padding].Clear();
        if (!value.TryWriteBytes(destination[padding..], out _, isUnsigned: true, isBigEndian: true))
        {
            throw new Exception($"BigInteger too big for a {destination.Length}-byte field! Length: {count}");
        }
    }
}
