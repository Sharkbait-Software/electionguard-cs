using ElectionGuard.Core.Crypto;
using System.Numerics;
using System.Runtime.CompilerServices;

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
    /// The inverse of <paramref name="a"/> modulo an odd <paramref name="modulus"/>, by the binary
    /// extended Euclidean algorithm over 64-bit limbs. Throws when there is none, that is when
    /// gcd(a, modulus) is not 1, and for an even modulus, which the halving steps cannot handle.
    ///
    /// VARIABLE TIME, FOR PUBLIC VALUES ONLY. The number of steps depends on the value, so this must
    /// never be given a secret. On the spec's 4096-bit p it takes about 2 ms, against 110 ms for
    /// Fermat's a^(p - 2) through <see cref="BigInteger.ModPow"/>, and allocates nothing but its
    /// result: the textbook division-based form allocated about 2 MB of BigIntegers per inverse.
    /// Decryption calls it once or twice per process, which is too few calls for tiered compilation
    /// to promote its loops past unoptimized code, hence AggressiveOptimization here and on its
    /// helpers: about 1 ms either way, against 12 ms unoptimized.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    internal static BigInteger ModInverseVariableTime(this BigInteger a, BigInteger modulus)
    {
        if (modulus <= 1 || modulus.IsEven)
        {
            throw new ArgumentException("The modulus must be odd and greater than 1.", nameof(modulus));
        }

        int n = (int)((modulus.GetBitLength() + 63) / 64);
        Span<ulong> u = n <= MaxStackAllocInverseLimbs ? stackalloc ulong[MaxStackAllocInverseLimbs] : new ulong[n];
        Span<ulong> v = n <= MaxStackAllocInverseLimbs ? stackalloc ulong[MaxStackAllocInverseLimbs] : new ulong[n];
        Span<ulong> x1 = n <= MaxStackAllocInverseLimbs ? stackalloc ulong[MaxStackAllocInverseLimbs] : new ulong[n];
        Span<ulong> x2 = n <= MaxStackAllocInverseLimbs ? stackalloc ulong[MaxStackAllocInverseLimbs] : new ulong[n];
        Span<ulong> m = n <= MaxStackAllocInverseLimbs ? stackalloc ulong[MaxStackAllocInverseLimbs] : new ulong[n];
        u = u[..n];
        v = v[..n];
        x1 = x1[..n];
        x2 = x2[..n];
        m = m[..n];

        MontgomeryContext.WriteLimbs(a.Mod(modulus), u);
        MontgomeryContext.WriteLimbs(modulus, m);
        m.CopyTo(v);
        x1.Clear();
        x1[0] = 1;
        x2.Clear();

        // Invariants: x1 * a = u and x2 * a = v (mod m), with x1, x2 in [0, m). Each pass halves
        // whichever of u and v is even and subtracts the smaller from the larger, so gcd(u, v) =
        // gcd(a, m) throughout; it ends when one of them reaches 1, or 0 if the gcd is not 1.
        while (true)
        {
            if (IsZero(u) || IsZero(v))
            {
                throw new ArgumentException("Value has no inverse modulo the given modulus.", nameof(a));
            }

            if (IsOne(u))
            {
                return MontgomeryContext.FromLimbs(x1);
            }

            if (IsOne(v))
            {
                return MontgomeryContext.FromLimbs(x2);
            }

            while ((u[0] & 1) == 0)
            {
                ShiftRightOne(u, 0);
                HalveMod(x1, m);
            }

            while ((v[0] & 1) == 0)
            {
                ShiftRightOne(v, 0);
                HalveMod(x2, m);
            }

            if (Compare(u, v) >= 0)
            {
                Subtract(u, v);
                SubtractMod(x1, x2, m);
            }
            else
            {
                Subtract(v, u);
                SubtractMod(x2, x1, m);
            }
        }
    }

    /// <summary>Limb buffers of <see cref="ModInverseVariableTime"/> wider than this go on the heap.</summary>
    private const int MaxStackAllocInverseLimbs = 80;

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static bool IsZero(ReadOnlySpan<ulong> value) => !value.ContainsAnyExcept(0UL);

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static bool IsOne(ReadOnlySpan<ulong> value) => value[0] == 1 && !value[1..].ContainsAnyExcept(0UL);

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static int Compare(ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right)
    {
        for (int i = left.Length - 1; i >= 0; i--)
        {
            if (left[i] != right[i])
            {
                return left[i] > right[i] ? 1 : -1;
            }
        }

        return 0;
    }

    /// <summary>value = value / 2, shifting <paramref name="topBit"/> into the most significant bit.</summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static void ShiftRightOne(Span<ulong> value, ulong topBit)
    {
        for (int i = 0; i < value.Length - 1; i++)
        {
            value[i] = (value[i] >> 1) | (value[i + 1] << 63);
        }

        value[^1] = (value[^1] >> 1) | (topBit << 63);
    }

    /// <summary>value = value + addend, returning the carry out of the top limb.</summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static ulong Add(Span<ulong> value, ReadOnlySpan<ulong> addend)
    {
        ulong carry = 0;
        for (int i = 0; i < value.Length; i++)
        {
            ulong sum = value[i] + addend[i];
            ulong carryOut = sum < value[i] ? 1UL : 0UL;
            sum += carry;
            carryOut |= sum < carry ? 1UL : 0UL;
            value[i] = sum;
            carry = carryOut;
        }

        return carry;
    }

    /// <summary>value = value - subtrahend, returning the borrow out of the top limb.</summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static ulong Subtract(Span<ulong> value, ReadOnlySpan<ulong> subtrahend)
    {
        ulong borrow = 0;
        for (int i = 0; i < value.Length; i++)
        {
            ulong difference = value[i] - subtrahend[i];
            ulong borrowOut = value[i] < subtrahend[i] ? 1UL : 0UL;
            borrowOut |= difference < borrow ? 1UL : 0UL;
            value[i] = difference - borrow;
            borrow = borrowOut;
        }

        return borrow;
    }

    /// <summary>value = value / 2 mod an odd modulus, for value in [0, modulus).</summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static void HalveMod(Span<ulong> value, ReadOnlySpan<ulong> modulus)
    {
        // An odd value is made even by adding the odd modulus; value + modulus may need one bit more
        // than the limbs hold, which the shift brings back in from the top.
        ulong carry = (value[0] & 1) == 0 ? 0 : Add(value, modulus);
        ShiftRightOne(value, carry);
    }

    /// <summary>value = value - subtrahend mod modulus, both in [0, modulus).</summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static void SubtractMod(Span<ulong> value, ReadOnlySpan<ulong> subtrahend, ReadOnlySpan<ulong> modulus)
    {
        if (Subtract(value, subtrahend) != 0)
        {
            Add(value, modulus);
        }
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
        WriteBigEndianPaddedCore(value, destination);
    }

    /// <summary>
    /// §5.1.1/§5.1.2 b(a, m): a non-negative value as exactly <paramref name="length"/> unsigned
    /// big-endian bytes, zero-padded on the left. Unlike IntegerModP/IntegerModQ.ToByteArray this
    /// does not reduce the value first, which is what the parameter base hash needs: it encodes p and
    /// q themselves (eq. 4), and reducing p mod p or q mod q would encode zero. Throws when the value
    /// is negative or wider than <paramref name="length"/>.
    /// </summary>
    public static byte[] ToBigEndianPadded(this BigInteger value, int length)
    {
        if (value.Sign < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Only non-negative values have a b(a, m) encoding.");
        }

        var bytes = new byte[length];
        WriteBigEndianPaddedCore(value, bytes);
        return bytes;
    }

    private static void WriteBigEndianPaddedCore(BigInteger value, Span<byte> destination)
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
