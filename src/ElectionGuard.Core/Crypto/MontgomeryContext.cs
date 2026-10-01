using ElectionGuard.Core.Models;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Numerics;

namespace ElectionGuard.Core.Crypto;

/// <summary>
/// Immutable per-modulus data required for Montgomery arithmetic mod p, plus the CIOS
/// (Coarsely Integrated Operand Scanning) Montgomery multiplication itself.
///
/// Note 3.5 observes that every exponentiation performed while encrypting and proving ballot
/// components has a base of either g or K, so implementations can precompute tables of powers of
/// those bases, and can further optimize by holding the table values in Montgomery form. This type
/// is the "Montgomery form" half of that note; <see cref="PowRadix"/> is the table half.
///
/// Montgomery form represents x as (x * R) mod p, where R = 2^(64 * LimbCount) is the smallest
/// power of the limb radix exceeding p. The point is that a modular multiply in this representation
/// needs no division: the reduction replaces `% p` with a multiply and a shift. That only pays off
/// on raw limbs. Measured against .NET's BigInteger, Montgomery form is worth about 4%, because
/// BigInteger's remainder is nearly as cheap as the two extra 4096-bit multiplies the reduction
/// costs. On ulong limbs it is worth roughly 2x, which is why this operates on <see cref="ulong"/>
/// spans rather than on <see cref="BigInteger"/>.
///
/// The arithmetic itself is endian-agnostic: it only ever reads and writes limbs as numbers. Byte
/// order matters in exactly two places, converting a <see cref="BigInteger"/> to limbs and back,
/// where the limb span is reinterpreted as bytes. Both handle either host, by reversing each limb's
/// bytes on a big-endian one. See <see cref="WriteLimbs(BigInteger, Span{ulong}, bool)"/>.
/// </summary>
internal sealed class MontgomeryContext
{
    /// <summary>
    /// Working buffers longer than this are heap-allocated per multiply rather than stack-allocated.
    /// The threshold covers the spec's 4096-bit p (64 limbs, 66 with the CIOS overflow limbs).
    /// </summary>
    private const int MaxStackAllocLimbs = 80;

    internal const int BitsPerLimb = 64;

    private MontgomeryContext(BigInteger modulus)
    {
        if (modulus <= 0 || modulus.IsEven)
        {
            // Montgomery reduction needs gcd(p, R) = 1, and R is a power of two.
            throw new ArgumentException("Montgomery arithmetic requires a positive odd modulus.", nameof(modulus));
        }

        Modulus = modulus;
        LimbCount = (int)((modulus.GetBitLength() + BitsPerLimb - 1) / BitsPerLimb);

        _modulusLimbs = ToLimbs(modulus, LimbCount);

        // n0inv = -p^-1 mod 2^64, by Hensel lifting. Each step doubles the number of correct bits,
        // so six steps take a 1-bit seed to the full 64. p is odd, so the seed is correct mod 2.
        ulong inverse = 1;
        for (int i = 0; i < 6; i++)
        {
            inverse = unchecked(inverse * (2 - _modulusLimbs[0] * inverse));
        }
        N0Inv = unchecked(0UL - inverse);

        BigInteger r = BigInteger.One << (LimbCount * BitsPerLimb);
        BigInteger rModP = r % modulus;

        _rSquared = ToLimbs(rModP * rModP % modulus, LimbCount);
        _one = ToLimbs(rModP, LimbCount);
    }

    private readonly ulong[] _modulusLimbs;
    private readonly ulong[] _rSquared;
    private readonly ulong[] _one;

    /// <summary>The modulus this context was built for.</summary>
    internal BigInteger Modulus { get; }

    /// <summary>Number of 64-bit limbs needed to hold a value less than <see cref="Modulus"/>.</summary>
    internal int LimbCount { get; }

    /// <summary>-Modulus^-1 mod 2^64, the per-limb reduction multiplier used by CIOS.</summary>
    internal ulong N0Inv { get; }

    /// <summary>Montgomery form of 1, that is R mod p. The multiplicative identity in this domain.</summary>
    internal ReadOnlySpan<ulong> One => _one;

    internal ReadOnlySpan<ulong> ModulusLimbs => _modulusLimbs;

    private static MontgomeryContext? _cached;

    /// <summary>
    /// The context for the currently active election parameters. Rebuilt only when
    /// <see cref="EGParameters"/> is pointed at a different p, which happens in tests that swap in
    /// a non-default parameter set.
    /// </summary>
    internal static MontgomeryContext Current => For(EGParameters.P);

    internal static MontgomeryContext For(BigInteger modulus)
    {
        MontgomeryContext? cached = _cached;
        if (cached is not null && cached.Modulus == modulus)
        {
            return cached;
        }

        MontgomeryContext created = new(modulus);
        _cached = created;
        return created;
    }

    /// <summary>Converts a value in [0, p) to its Montgomery form, (value * R) mod p.</summary>
    internal void ToMontgomery(BigInteger value, Span<ulong> result)
    {
        Span<ulong> plain = LimbCount <= MaxStackAllocLimbs ? stackalloc ulong[MaxStackAllocLimbs] : new ulong[LimbCount];
        plain = plain[..LimbCount];

        WriteLimbs(value, plain);

        // Multiplying by R^2 leaves value * R^2 * R^-1 = value * R.
        Multiply(plain, _rSquared, result);
    }

    /// <summary>Converts a Montgomery-form value back to an ordinary residue in [0, p).</summary>
    internal BigInteger FromMontgomery(ReadOnlySpan<ulong> montgomery)
    {
        Span<ulong> plain = LimbCount <= MaxStackAllocLimbs ? stackalloc ulong[MaxStackAllocLimbs] : new ulong[LimbCount];
        plain = plain[..LimbCount];

        Span<ulong> one = LimbCount <= MaxStackAllocLimbs ? stackalloc ulong[MaxStackAllocLimbs] : new ulong[LimbCount];
        one = one[..LimbCount];
        one.Clear();
        one[0] = 1;

        // Multiplying by a plain 1 divides out the R factor.
        Multiply(montgomery, one, plain);
        return FromLimbs(plain);
    }

    /// <summary>
    /// CIOS Montgomery multiplication: result = (a * b * R^-1) mod p.
    ///
    /// Both operands must already be reduced, that is less than p. <paramref name="result"/> may
    /// alias either operand, because the running sum lives in a separate buffer and is only copied
    /// out at the end. That makes squaring in place safe.
    /// </summary>
    internal void Multiply(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> result)
    {
        int s = LimbCount;
        ulong[] n = _modulusLimbs;
        ulong n0 = N0Inv;

        // CIOS keeps a running sum two limbs wider than the modulus. The classic bound is t < 2p,
        // and p here fills its top limb completely (the spec's p begins FFFF...), so there are no
        // spare high bits to absorb the overflow and the extra limb is genuinely needed.
        Span<ulong> t = s + 2 <= MaxStackAllocLimbs ? stackalloc ulong[MaxStackAllocLimbs] : new ulong[s + 2];
        t = t[..(s + 2)];
        t.Clear();

        for (int i = 0; i < s; i++)
        {
            ulong bi = b[i];

            // Accumulate a * b[i] into t. Each term is bounded by (2^64-1)^2 + 2*(2^64-1) = 2^128-1,
            // so a UInt128 holds it exactly and the carry stays below 2^64.
            UInt128 carry = 0;
            for (int j = 0; j < s; j++)
            {
                UInt128 sum = (UInt128)a[j] * bi + t[j] + (ulong)carry;
                carry = sum >> BitsPerLimb;
                t[j] = (ulong)sum;
            }

            UInt128 high = (UInt128)t[s] + carry;
            t[s] = (ulong)high;
            t[s + 1] = (ulong)(high >> BitsPerLimb);

            // Choose m so that t + m*p is divisible by 2^64, then shift that now-zero limb away.
            // This is the step that stands in for division by p.
            ulong m = unchecked(t[0] * n0);
            UInt128 reduceCarry = ((UInt128)m * n[0] + t[0]) >> BitsPerLimb;
            for (int j = 1; j < s; j++)
            {
                UInt128 sum = (UInt128)m * n[j] + t[j] + (ulong)reduceCarry;
                reduceCarry = sum >> BitsPerLimb;
                t[j - 1] = (ulong)sum;
            }

            UInt128 last = (UInt128)t[s] + reduceCarry;
            t[s - 1] = (ulong)last;
            t[s] = t[s + 1] + (ulong)(last >> BitsPerLimb);
        }

        ConditionalSubtractModulus(t, result);
    }

    /// <summary>
    /// CIOS leaves the running sum in [0, 2p). Bring it into [0, p) with at most one subtraction.
    /// </summary>
    private void ConditionalSubtractModulus(ReadOnlySpan<ulong> t, Span<ulong> result)
    {
        int s = LimbCount;
        ulong[] n = _modulusLimbs;

        // t occupies s+1 meaningful limbs. A non-zero top limb already exceeds p, since p < R.
        bool subtract = t[s] != 0;
        if (!subtract)
        {
            subtract = true;
            for (int j = s - 1; j >= 0; j--)
            {
                if (t[j] != n[j])
                {
                    subtract = t[j] > n[j];
                    break;
                }
            }
        }

        if (!subtract)
        {
            t[..s].CopyTo(result);
            return;
        }

        ulong borrow = 0;
        for (int j = 0; j < s; j++)
        {
            ulong tj = t[j];
            ulong nj = n[j];
            result[j] = unchecked(tj - nj - borrow);

            // Borrows out when tj < nj + borrow, evaluated so that nj + borrow cannot overflow.
            borrow = (tj < nj || (tj == nj && borrow != 0)) ? 1UL : 0UL;
        }
    }

    private static ulong[] ToLimbs(BigInteger value, int limbCount)
    {
        ulong[] limbs = new ulong[limbCount];
        WriteLimbs(value, limbs);
        return limbs;
    }

    /// <summary>
    /// True when a limb's bytes must be reversed after reinterpreting the span, that is on a
    /// big-endian host. <see cref="BitConverter.IsLittleEndian"/> is a JIT-time constant, so the
    /// swap loops below are eliminated entirely on a little-endian build.
    /// </summary>
    private static bool SwapLimbBytes => !BitConverter.IsLittleEndian;

    /// <summary>
    /// Writes a non-negative value into <paramref name="limbs"/> as little-endian 64-bit limbs.
    ///
    /// Reinterpreting the ulong span as bytes is what makes this one copy rather than a shift-and-or
    /// loop over every byte, with no intermediate array. The catch is that the reinterpretation is
    /// the host's byte order, while BigInteger was asked for little-endian: on a little-endian host
    /// those agree and nothing more is needed, and on a big-endian one each limb comes out
    /// byte-reversed, so reversing it again puts it right.
    /// </summary>
    private static void WriteLimbs(BigInteger value, Span<ulong> limbs)
    {
        WriteLimbs(value, limbs, SwapLimbBytes);
    }

    /// <summary>
    /// <paramref name="swapLimbBytes"/> is a parameter rather than read from
    /// <see cref="BitConverter.IsLittleEndian"/> so that tests can drive the big-endian path on a
    /// little-endian machine, which is otherwise code that ships without ever having run.
    /// </summary>
    internal static void WriteLimbs(BigInteger value, Span<ulong> limbs, bool swapLimbBytes)
    {
        limbs.Clear();
        if (!value.TryWriteBytes(MemoryMarshal.AsBytes(limbs), out _, isUnsigned: true, isBigEndian: false))
        {
            throw new ArgumentException("Value does not fit in the requested number of limbs.", nameof(value));
        }

        if (swapLimbBytes)
        {
            for (int i = 0; i < limbs.Length; i++)
            {
                limbs[i] = BinaryPrimitives.ReverseEndianness(limbs[i]);
            }
        }
    }

    internal static BigInteger FromLimbs(ReadOnlySpan<ulong> limbs)
    {
        return FromLimbs(limbs, SwapLimbBytes);
    }

    /// <inheritdoc cref="WriteLimbs(BigInteger, Span{ulong}, bool)"/>
    internal static BigInteger FromLimbs(ReadOnlySpan<ulong> limbs, bool swapLimbBytes)
    {
        // isUnsigned means a set top bit is read as magnitude rather than sign, so unlike a signed
        // conversion this needs no extra zero byte on the end.
        if (!swapLimbBytes)
        {
            return new BigInteger(MemoryMarshal.AsBytes(limbs), isUnsigned: true, isBigEndian: false);
        }

        // Reversing into a scratch copy, because the caller's limbs are the live value and must not
        // be disturbed. This is the big-endian path, so it never runs on a little-endian build.
        Span<ulong> reversed = limbs.Length <= MaxStackAllocLimbs
            ? stackalloc ulong[MaxStackAllocLimbs]
            : new ulong[limbs.Length];
        reversed = reversed[..limbs.Length];

        for (int i = 0; i < limbs.Length; i++)
        {
            reversed[i] = BinaryPrimitives.ReverseEndianness(limbs[i]);
        }

        return new BigInteger(MemoryMarshal.AsBytes(reversed), isUnsigned: true, isBigEndian: false);
    }
}
