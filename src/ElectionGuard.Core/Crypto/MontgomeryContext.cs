using ElectionGuard.Core.Models;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
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
    /// The threshold covers the spec's 4096-bit p (64 limbs, 65 with the CIOS overflow limb).
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

        FromMontgomeryInto(montgomery, plain);
        return FromLimbs(plain);
    }

    /// <summary>
    /// Converts a Montgomery-form value back to an ordinary residue in [0, p), leaving it as limbs in
    /// <paramref name="plain"/> rather than building a BigInteger. <paramref name="plain"/> may alias
    /// <paramref name="montgomery"/>.
    /// </summary>
    internal void FromMontgomeryInto(ReadOnlySpan<ulong> montgomery, Span<ulong> plain)
    {
        Span<ulong> one = LimbCount <= MaxStackAllocLimbs ? stackalloc ulong[MaxStackAllocLimbs] : new ulong[LimbCount];
        one = one[..LimbCount];
        one.Clear();
        one[0] = 1;

        // Multiplying by a plain 1 divides out the R factor. CIOS leaves the result fully reduced.
        Multiply(montgomery, one, plain);
    }

    /// <summary>
    /// Writes a Montgomery-form value, converted back to an ordinary residue, as the fixed-width
    /// big-endian bytes <see cref="IntegerModP.ToByteArray"/> would produce for it.
    /// </summary>
    internal void WriteBigEndian(ReadOnlySpan<ulong> montgomery, Span<byte> destination)
    {
        Span<ulong> plain = LimbCount <= MaxStackAllocLimbs ? stackalloc ulong[MaxStackAllocLimbs] : new ulong[LimbCount];
        plain = plain[..LimbCount];

        FromMontgomeryInto(montgomery, plain);
        WriteLimbsBigEndian(plain, destination);
    }

    /// <summary>
    /// Writes ordinary (not Montgomery-form) little-endian limbs as an unsigned big-endian integer
    /// filling all of <paramref name="destination"/>, zero-padded on the left. For a 512-byte
    /// destination these are exactly the bytes <see cref="IntegerModP.ToByteArray"/> produces for
    /// the same value. Limbs past the end of the destination must be zero; a value too wide for it
    /// throws, as ToByteArray does.
    ///
    /// The limbs are read as numbers, so this is correct on either host byte order.
    /// </summary>
    internal static void WriteLimbsBigEndian(ReadOnlySpan<ulong> limbs, Span<byte> destination)
    {
        destination.Clear();
        for (int i = 0; i < limbs.Length; i++)
        {
            int end = destination.Length - i * sizeof(ulong);
            ulong limb = limbs[i];
            if (end >= sizeof(ulong))
            {
                BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(end - sizeof(ulong), sizeof(ulong)), limb);
                continue;
            }

            // The destination ends partway through, or before, this limb: whatever does not fit
            // must be zero, or the value is too wide for the destination.
            for (int b = 0; b < sizeof(ulong); b++, limb >>= 8)
            {
                int index = end - 1 - b;
                if (index >= 0)
                {
                    destination[index] = (byte)limb;
                }
                else if ((byte)limb != 0)
                {
                    throw new ArgumentException("Value does not fit in the destination.", nameof(destination));
                }
            }
        }
    }

    /// <summary>
    /// CIOS Montgomery multiplication: result = (a * b * R^-1) mod p.
    ///
    /// Both operands must already be reduced, that is less than p. <paramref name="result"/> may
    /// alias either operand, because the running sum lives in a separate buffer and is only copied
    /// out at the end. That makes squaring in place safe.
    ///
    /// Each outer step folds the row a * b[i] and the reduction row m * p into a single pass over
    /// t, carrying two independent chains (one per row) instead of walking t twice. That halves the
    /// loads and stores of t, and the two chains give the CPU independent multiplies to overlap.
    /// m depends only on the lowest limb of t + a * b[i], so it is known before the pass begins.
    ///
    /// The limb arithmetic is written for the JIT rather than for brevity, because this is where a
    /// table-free exponentiation spends nearly all of its time:
    /// - <see cref="Math.BigMul(ulong, ulong, out ulong)"/> compiles to one mulx, where the previous
    ///   version widened to <see cref="UInt128"/> and added through it.
    /// - Carries are ulong adds with the carry recovered by comparison (sum &lt; addend), which the
    ///   JIT turns into a branch-free compare and setb. Each step adds the limb already in t before
    ///   the incoming carry, so only the second add sits on the loop-carried dependency chain.
    /// - Limbs are reached through refs, after one up-front length check, so the inner loop carries
    ///   no bounds checks. The length check is what keeps that safe.
    /// - <see cref="SkipLocalsInitAttribute"/> stops the stackalloc from being zeroed on entry; only
    ///   the s + 1 limbs actually used are cleared.
    ///
    /// What is left is bound by instruction count, about 17-21 per limb product, not by the carry
    /// chain's latency: product scanning (Comba/FIPS), 4x unrolling and Bmi2 high-only multiplies
    /// were all measured and tied with this. On .NET 9 the floor is set by three things C# cannot
    /// avoid: the out parameter of BigMul round-trips through the stack, each carry costs a
    /// compare/setb/movzx, and there is no add-with-carry (adc/adcx/adox) intrinsic.
    ///
    /// Measured in-process against the previous separate-pass UInt128 kernel, single-threaded with
    /// interleaved runs on the spec's 4096-bit p (x64, .NET 9, scalar path): 1.13-1.17x faster
    /// (about 9.3 us to 8.2 us per multiply).
    /// </summary>
    [SkipLocalsInit]
    internal void Multiply(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> result)
    {
        int s = LimbCount;
        CheckLengths(a.Length, s);
        CheckLengths(b.Length, s);
        CheckLengths(result.Length, s);

        ulong n0 = N0Inv;

        // The classic CIOS bound is t < 2p, and p here fills its top limb completely (the spec's p
        // begins FFFF...), so there are no spare high bits to absorb the overflow and limb s is
        // genuinely needed. It only ever holds 0 or 1.
        Span<ulong> t = s + 1 <= MaxStackAllocLimbs ? stackalloc ulong[MaxStackAllocLimbs] : new ulong[s + 1];
        t = t[..(s + 1)];
        t.Clear();

        ref ulong ap = ref MemoryMarshal.GetReference(a);
        ref ulong bp = ref MemoryMarshal.GetReference(b);
        ref ulong np = ref MemoryMarshal.GetArrayDataReference(_modulusLimbs);
        ref ulong tp = ref MemoryMarshal.GetReference(t);

        for (int i = 0; i < s; i++)
        {
            ulong bi = Unsafe.Add(ref bp, i);

            // Limb 0: form the low limb of t + a * b[i], choose m so that adding m * p zeroes it,
            // and drop the zero limb. Choosing m is the step that stands in for division by p.
            ulong productHigh = Math.BigMul(ap, bi, out ulong productLow);
            productLow += tp;
            productHigh += productLow < tp ? 1UL : 0UL;

            ulong m = unchecked(productLow * n0);
            ulong reduceHigh = Math.BigMul(m, np, out ulong reduceLow);
            reduceLow += productLow;
            reduceHigh += reduceLow < productLow ? 1UL : 0UL;

            ulong productCarry = productHigh;
            ulong reduceCarry = reduceHigh;

            // Each sum below is at most (2^64-1)^2 + 2(2^64-1) = 2^128-1, so the high word absorbs
            // both carries without overflowing.
            for (int j = 1; j < s; j++)
            {
                ulong tj = Unsafe.Add(ref tp, j);

                productHigh = Math.BigMul(Unsafe.Add(ref ap, j), bi, out productLow);
                productLow += tj;
                productHigh += productLow < tj ? 1UL : 0UL;
                productLow += productCarry;
                productHigh += productLow < productCarry ? 1UL : 0UL;
                productCarry = productHigh;

                reduceHigh = Math.BigMul(m, Unsafe.Add(ref np, j), out reduceLow);
                reduceLow += productLow;
                reduceHigh += reduceLow < productLow ? 1UL : 0UL;
                reduceLow += reduceCarry;
                reduceHigh += reduceLow < reduceCarry ? 1UL : 0UL;
                reduceCarry = reduceHigh;

                Unsafe.Add(ref tp, j - 1) = reduceLow;
            }

            // Both chains end on limb s. Each can carry one bit past it, and the bound t < 2p means
            // they never both do.
            ulong top = Unsafe.Add(ref tp, s) + productCarry;
            ulong topCarry = top < productCarry ? 1UL : 0UL;
            top += reduceCarry;
            topCarry += top < reduceCarry ? 1UL : 0UL;

            Unsafe.Add(ref tp, s - 1) = top;
            Unsafe.Add(ref tp, s) = topCarry;
        }

        ConditionalSubtractModulus(t, result);
    }

    /// <summary>
    /// Montgomery squaring: result = (a * a * R^-1) mod p.
    ///
    /// Squarings are about three quarters of the multiplications in a table-free exponentiation (a
    /// 256-bit exponent with a 4-bit window costs 256 squarings against 79 general multiplies), so
    /// this is the hot path of every exponentiation whose base has no precomputed table -- which is
    /// most of Verifications 6 and 7.
    ///
    /// CIOS cannot exploit a = b, because it interleaves each row of the product with a reduction
    /// step. This instead separates the two (SOS, Separated Operand Scanning): it forms the full
    /// 2s-limb square first, computing each cross product a[i] * a[j] (i &lt; j) once and doubling
    /// the sum rather than computing it twice, then reduces. That is s(s+1)/2 limb products for the
    /// square plus s^2 for the reduction, against 2s^2 for <see cref="Multiply"/>.
    ///
    /// Both phases walk their rows two at a time, the same way <see cref="Multiply"/> fuses its
    /// product and reduction rows: one pass over t carries two independent carry chains, halving the
    /// loads and stores of t. Rows i and i+1 are offset by one limb, so row i+1 joins one step late;
    /// in the reduction, that one step is what makes limb i+1 final, so that m for row i+1 can be
    /// chosen. An odd row left over runs alone.
    ///
    /// <paramref name="a"/> must be reduced, and <paramref name="result"/> may alias it, because the
    /// working value lives in a separate buffer until the final copy. The limb arithmetic follows
    /// the same JIT-oriented style as <see cref="Multiply"/>; see there for why.
    ///
    /// Measured the same way as <see cref="Multiply"/>, against the previous one-row-at-a-time
    /// UInt128 version: 1.03x faster (about 6.6 us to 6.45 us). Porting only the BigMul/ref style
    /// without the row pairing measured 0.97x, a slowdown; the pairing is what makes it pay. A full
    /// table-free exponentiation with a 256-bit exponent (4-bit window, about 3/4 squarings) went
    /// from 2.38 ms to 2.24 ms, 1.07x.
    /// </summary>
    [SkipLocalsInit]
    internal void Square(ReadOnlySpan<ulong> a, Span<ulong> result)
    {
        int s = LimbCount;
        CheckLengths(a.Length, s);
        CheckLengths(result.Length, s);

        ulong n0 = N0Inv;

        // The square occupies 2s limbs; the extra limb holds the reduction's final carry, which
        // plays the same role as the overflow limb in Multiply.
        int width = 2 * s + 1;
        Span<ulong> t = width <= 2 * MaxStackAllocLimbs + 1 ? stackalloc ulong[2 * MaxStackAllocLimbs + 1] : new ulong[width];
        t = t[..width];

        ref ulong ap = ref MemoryMarshal.GetReference(a);
        ref ulong np = ref MemoryMarshal.GetArrayDataReference(_modulusLimbs);
        ref ulong tp = ref MemoryMarshal.GetReference(t);

        // The cross-product rows below accumulate into t[1 .. s-1] and assign everything above
        // that, except t[2s-1], which only the doubling reaches. Those are the only limbs that need
        // to start at zero; t[0] is the doubling's input too.
        t[..s].Clear();
        t[2 * s - 1] = 0;

        // Cross products, each pair once. Row i writes t[2i+1 .. i+s-1] and then sets t[i+s], which
        // no earlier row has reached (row i-1 stops at t[i+s-1]), so assigning rather than adding
        // the final carry is correct. Rows go in pairs; a pair (i, i+1) writes t[2i+1 .. i+s-1] and
        // sets t[i+s] and t[i+s+1], which is exactly what the two rows would do one after the other.
        int crossRow = 0;
        for (; crossRow + 2 < s; crossRow += 2)
        {
            int i = crossRow;
            ulong a0 = Unsafe.Add(ref ap, i);
            ulong a1 = Unsafe.Add(ref ap, i + 1);

            // Row i alone covers limbs 2i+1 and 2i+2; row i+1 starts at 2i+3.
            ref ulong first = ref Unsafe.Add(ref tp, 2 * i + 1);
            ulong x = first;
            ulong high0 = Math.BigMul(a0, a1, out ulong low0);
            low0 += x;
            high0 += low0 < x ? 1UL : 0UL;
            first = low0;
            ulong carry0 = high0;

            ref ulong second = ref Unsafe.Add(ref tp, 2 * i + 2);
            x = second;
            high0 = Math.BigMul(a0, Unsafe.Add(ref ap, i + 2), out low0);
            low0 += x;
            high0 += low0 < x ? 1UL : 0UL;
            low0 += carry0;
            high0 += low0 < carry0 ? 1UL : 0UL;
            second = low0;
            carry0 = high0;

            ulong carry1 = 0;
            ulong high1;
            ulong low1;
            for (int j = i + 3; j < s; j++)
            {
                ref ulong limb = ref Unsafe.Add(ref tp, i + j);
                ulong tij = limb;

                high0 = Math.BigMul(a0, Unsafe.Add(ref ap, j), out low0);
                low0 += tij;
                high0 += low0 < tij ? 1UL : 0UL;
                low0 += carry0;
                high0 += low0 < carry0 ? 1UL : 0UL;
                carry0 = high0;

                high1 = Math.BigMul(a1, Unsafe.Add(ref ap, j - 1), out low1);
                low1 += low0;
                high1 += low1 < low0 ? 1UL : 0UL;
                low1 += carry1;
                high1 += low1 < carry1 ? 1UL : 0UL;
                carry1 = high1;

                limb = low1;
            }

            // Limb i+s is fresh (row i-1 stopped at i+s-1): row i's carry, plus row i+1's last
            // product and carry. Limb i+s+1 takes row i+1's final carry.
            high1 = Math.BigMul(a1, Unsafe.Add(ref ap, s - 1), out low1);
            low1 += carry0;
            high1 += low1 < carry0 ? 1UL : 0UL;
            low1 += carry1;
            high1 += low1 < carry1 ? 1UL : 0UL;
            Unsafe.Add(ref tp, i + s) = low1;
            Unsafe.Add(ref tp, i + s + 1) = high1;
        }

        for (int i = crossRow; i < s - 1; i++)
        {
            ulong ai = Unsafe.Add(ref ap, i);
            ulong carry = 0;
            for (int j = i + 1; j < s; j++)
            {
                ref ulong limb = ref Unsafe.Add(ref tp, i + j);
                ulong tij = limb;

                ulong high = Math.BigMul(ai, Unsafe.Add(ref ap, j), out ulong low);
                low += tij;
                high += low < tij ? 1UL : 0UL;
                low += carry;
                high += low < carry ? 1UL : 0UL;

                limb = low;
                carry = high;
            }

            Unsafe.Add(ref tp, i + s) = carry;
        }

        // Double the cross products and add the diagonal terms a[i]^2 at limb 2i, in one pass over
        // limb pairs. The cross products sum to less than a^2 / 2 < R^2 / 2, so the doubling shifts
        // no bit out of the top limb, and the total is a^2 < R^2, so the final carry is zero.
        ulong shiftedOut = 0;
        ulong diagonalCarry = 0;
        for (int i = 0; i < s; i++)
        {
            ref ulong lowLimb = ref Unsafe.Add(ref tp, 2 * i);
            ref ulong highLimb = ref Unsafe.Add(ref tp, 2 * i + 1);
            ulong crossLow = lowLimb;
            ulong crossHigh = highLimb;

            ulong doubledLow = (crossLow << 1) | shiftedOut;
            ulong doubledHigh = (crossHigh << 1) | (crossLow >> 63);
            shiftedOut = crossHigh >> 63;

            ulong ai = Unsafe.Add(ref ap, i);
            ulong squareHigh = Math.BigMul(ai, ai, out ulong squareLow);

            ulong low = doubledLow + squareLow;
            ulong lowCarry = low < squareLow ? 1UL : 0UL;
            low += diagonalCarry;
            lowCarry += low < diagonalCarry ? 1UL : 0UL;

            ulong high = doubledHigh + squareHigh;
            ulong highCarry = high < squareHigh ? 1UL : 0UL;
            high += lowCarry;
            highCarry += high < lowCarry ? 1UL : 0UL;

            lowLimb = low;
            highLimb = high;
            diagonalCarry = highCarry;
        }

        // Montgomery reduction, one limb at a time: add m * p to zero limb i. Each row's carry lands
        // on limb i+s, together with the overflow left there by the previous row; that sum is at most
        // 2(2^64 - 1) + 1, so the overflow out of it is a single bit. A pair (i, i+1) does the same
        // across limbs i+s and i+s+1: row i's carry and the incoming overflow meet on i+s (at most one
        // bit out, since both are below 2^64 and the overflow is a bit), row i+1's last product
        // absorbs that limb with its high word below 2^64, and that high word plus the one bit lands
        // on i+s+1, leaving again a single-bit overflow for the next pair.
        ulong overflow = 0;
        int paired = s & ~1;
        for (int i = 0; i < paired; i += 2)
        {
            ref ulong row = ref Unsafe.Add(ref tp, i);

            // Row i, limbs 0 and 1. Limb 0 becomes zero by the choice of m0.
            ulong m0 = unchecked(row * n0);
            ulong high0 = Math.BigMul(m0, np, out ulong low0);
            low0 += row;
            high0 += low0 < row ? 1UL : 0UL;
            ulong carry0 = high0;

            ulong x = Unsafe.Add(ref row, 1);
            high0 = Math.BigMul(m0, Unsafe.Add(ref np, 1), out low0);
            low0 += x;
            high0 += low0 < x ? 1UL : 0UL;
            low0 += carry0;
            high0 += low0 < carry0 ? 1UL : 0UL;
            carry0 = high0;

            // Limb i+1 is now final for row i, so m1 is known and row i+1 can start.
            ulong m1 = unchecked(low0 * n0);
            ulong high1 = Math.BigMul(m1, np, out ulong low1);
            low1 += low0;
            high1 += low1 < low0 ? 1UL : 0UL;
            ulong carry1 = high1;

            for (int j = 2; j < s; j++)
            {
                ref ulong limb = ref Unsafe.Add(ref row, j);
                ulong tij = limb;

                high0 = Math.BigMul(m0, Unsafe.Add(ref np, j), out low0);
                low0 += tij;
                high0 += low0 < tij ? 1UL : 0UL;
                low0 += carry0;
                high0 += low0 < carry0 ? 1UL : 0UL;
                carry0 = high0;

                high1 = Math.BigMul(m1, Unsafe.Add(ref np, j - 1), out low1);
                low1 += low0;
                high1 += low1 < low0 ? 1UL : 0UL;
                low1 += carry1;
                high1 += low1 < carry1 ? 1UL : 0UL;
                carry1 = high1;

                limb = low1;
            }

            ref ulong topLimb = ref Unsafe.Add(ref row, s);
            ulong top = topLimb + carry0;
            ulong topCarry = top < carry0 ? 1UL : 0UL;
            top += overflow;
            topCarry += top < overflow ? 1UL : 0UL;

            high1 = Math.BigMul(m1, Unsafe.Add(ref np, s - 1), out low1);
            low1 += top;
            high1 += low1 < top ? 1UL : 0UL;
            low1 += carry1;
            high1 += low1 < carry1 ? 1UL : 0UL;
            topLimb = low1;

            ref ulong nextLimb = ref Unsafe.Add(ref row, s + 1);
            ulong next = nextLimb + high1;
            ulong nextCarry = next < high1 ? 1UL : 0UL;
            next += topCarry;
            nextCarry += next < topCarry ? 1UL : 0UL;
            nextLimb = next;
            overflow = nextCarry;
        }

        for (int i = paired; i < s; i++)
        {
            ref ulong row = ref Unsafe.Add(ref tp, i);
            ulong m = unchecked(row * n0);
            ulong carry = 0;
            for (int j = 0; j < s; j++)
            {
                ref ulong limb = ref Unsafe.Add(ref row, j);
                ulong tij = limb;

                ulong high = Math.BigMul(m, Unsafe.Add(ref np, j), out ulong low);
                low += tij;
                high += low < tij ? 1UL : 0UL;
                low += carry;
                high += low < carry ? 1UL : 0UL;

                limb = low;
                carry = high;
            }

            ref ulong topLimb = ref Unsafe.Add(ref row, s);
            ulong top = topLimb + carry;
            ulong topCarry = top < carry ? 1UL : 0UL;
            top += overflow;
            topCarry += top < overflow ? 1UL : 0UL;

            topLimb = top;
            overflow = topCarry;
        }

        // What remains is (a^2 + M*p) / R < 2p, held in t[s .. 2s] with the overflow bit on top --
        // the same shape CIOS leaves, so the same final subtraction applies.
        t[2 * s] = overflow;
        ConditionalSubtractModulus(t.Slice(s, s + 1), result);
    }

    private static void CheckLengths(int length, int limbCount)
    {
        // The kernels above index through refs, with no per-access bounds check, so this one check
        // is all that stands between a short span and reading or writing past it.
        if (length < limbCount)
        {
            throw new ArgumentException($"Expected at least {limbCount} limbs, got {length}.");
        }
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
