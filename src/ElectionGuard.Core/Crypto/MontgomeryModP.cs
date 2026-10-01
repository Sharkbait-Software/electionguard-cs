using ElectionGuard.Core.Extensions;
using System.Numerics;

namespace ElectionGuard.Core.Crypto;

/// <summary>
/// §3.1.1 exponentiation mod large prime p, computed in Montgomery form. Note 3.5.
///
/// This is the accelerated counterpart to <see cref="IntegerModP"/>, which is deliberately left
/// untouched: it stays the straightforward BigInteger implementation, with no table lookups and no
/// branches on its hot path, for the many operations that gain nothing from precomputation.
///
/// <see cref="PowModP(IntegerModP, IntegerModQ)"/> works with no setup at all, using a windowed
/// square-and-multiply over Montgomery limbs, which is roughly twice as fast as
/// <see cref="IntegerModP.PowModP(BigInteger, BigInteger)"/>. If a caller has opted in by
/// precomputing a table for the base via <see cref="PowRadixRegistry"/>, it uses that instead and is
/// roughly thirty times as fast. Note 3.5 predicts "an order of magnitude or more"; both halves of
/// the note, the table and the Montgomery form, are needed to get there.
///
/// This is a static class rather than a Montgomery-form value type, which is where it started and
/// what the reference Kotlin implementation has. A value type bought nothing here: Montgomery form
/// is only worth entering to run a chain of multiplications and leave again, which is exactly an
/// exponentiation, so every caller in this library wants one call rather than a representation to
/// hold. Carrying one meant every value dragged a reference to its modulus data, and that reference
/// is the only thing a struct could not supply for itself.
/// </summary>
public static class MontgomeryModP
{
    /// <summary>
    /// Window width for the table-free exponentiation. Four bits costs 15 setup multiplies and then
    /// one multiply per nibble, which beats both binary square-and-multiply and wider windows at the
    /// 256-bit exponent size the spec uses.
    /// </summary>
    private const int TableFreeWindowBits = 4;

    private const int TableFreeWindowSize = 1 << TableFreeWindowBits;

    /// <summary>
    /// Exponents this short use a 1-bit window instead of a 4-bit one.
    ///
    /// A 4-bit window costs 15 multiplications to set up and then saves three quarters of the
    /// multiplications in the main loop, so for an n-bit exponent it beats a 1-bit window only once
    /// 2n exceeds 1.25n + 15, that is above roughly 20 bits. Below that the setup is pure overhead.
    /// Nonces drawn from Z_q are always far above the threshold; small public exponents such as a
    /// ballot weight or a guardian index are not, and without this they would pay 15 multiplications
    /// to save two.
    /// </summary>
    private const int NarrowWindowMaxExponentBytes = 4;

    private const int NarrowWindowBits = 1;

    /// <summary>Buffers longer than this are heap-allocated rather than stack-allocated.</summary>
    private const int MaxStackAllocLimbs = 80;

    /// <summary>
    /// Computes basis^exponent mod p, using a precomputed <see cref="PowRadix"/> table for
    /// <paramref name="basis"/> when one has been registered, and a table-free windowed Montgomery
    /// exponentiation otherwise.
    /// </summary>
    public static IntegerModP PowModP(IntegerModP basis, IntegerModQ exponent)
    {
        return PowModP(basis.ToBigInteger(), exponent);
    }

    /// <summary>
    /// Computes basis^exponent mod p. The BigInteger overload exists because the generator is held
    /// as <see cref="Models.EGParameters.G"/>, a BigInteger, at most call sites.
    /// </summary>
    public static IntegerModP PowModP(BigInteger basis, IntegerModQ exponent)
    {
        if (PowRadixRegistry.TryGet(basis, out PowRadix radix))
        {
            return radix.Pow(exponent);
        }

        return PowModPTableFree(basis, exponent.ToByteArray());
    }

    /// <inheritdoc cref="PowModP(BigInteger, BigInteger)"/>
    public static IntegerModP PowModP(IntegerModP basis, BigInteger exponent)
    {
        return PowModP(basis.ToBigInteger(), exponent);
    }

    /// <summary>
    /// Computes basis^exponent mod p for an exponent that is not an element of Z_q.
    ///
    /// This overload never consults the precomputed tables, and that is the point rather than an
    /// oversight. A <see cref="PowRadix"/> table is sized to exponents drawn from Z_q, and the
    /// exponents reaching this overload are not: the subgroup checks of Verifications 2, 6 and 7
    /// raise a value to the power q itself. Routing q through <see cref="IntegerModQ"/> would reduce
    /// it to zero, turning "x^q mod p = 1" into "x^0 = 1" - a check that passes for every input,
    /// silently accepting values outside the subgroup. Taking the exponent as a BigInteger keeps
    /// that from being expressible.
    ///
    /// The table-free Montgomery path still applies, so these calls are about twice as fast as
    /// <see cref="IntegerModP.PowModP(BigInteger, BigInteger)"/>.
    /// </summary>
    public static IntegerModP PowModP(BigInteger basis, BigInteger exponent)
    {
        if (exponent.Sign < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(exponent), exponent, "Exponent must not be negative.");
        }

        return PowModPTableFree(basis, exponent.ToByteArray(isUnsigned: true, isBigEndian: true));
    }

    private static IntegerModP PowModPTableFree(BigInteger basis, ReadOnlySpan<byte> exponentBigEndian)
    {
        MontgomeryContext context = MontgomeryContext.Current;
        Span<ulong> result = context.LimbCount <= MaxStackAllocLimbs
            ? stackalloc ulong[MaxStackAllocLimbs]
            : new ulong[context.LimbCount];
        result = result[..context.LimbCount];

        PowInto(basis, exponentBigEndian, context, result);
        return new IntegerModP(context.FromMontgomery(result));
    }

    /// <summary>
    /// One modular multiplication routed through Montgomery form, for tests that need to exercise
    /// the limb arithmetic directly rather than through an exponentiation.
    ///
    /// Not public, and not a performance win: entering and leaving Montgomery form costs two
    /// multiplications of its own, so a single product is cheaper as <c>a * b % p</c>. Montgomery
    /// form pays for itself only across the long chain of multiplications inside an exponentiation.
    /// </summary>
    internal static IntegerModP MultiplyMod(IntegerModP a, IntegerModP b)
    {
        MontgomeryContext context = MontgomeryContext.Current;
        int s = context.LimbCount;

        Span<ulong> left = s <= MaxStackAllocLimbs ? stackalloc ulong[MaxStackAllocLimbs] : new ulong[s];
        Span<ulong> right = s <= MaxStackAllocLimbs ? stackalloc ulong[MaxStackAllocLimbs] : new ulong[s];
        left = left[..s];
        right = right[..s];

        context.ToMontgomery(a.ToBigInteger(), left);
        context.ToMontgomery(b.ToBigInteger(), right);
        context.Multiply(left, right, left);

        return new IntegerModP(context.FromMontgomery(left));
    }

    /// <summary>
    /// One modular squaring through <see cref="MontgomeryContext.Square"/>, for tests that need to
    /// exercise the dedicated squaring routine directly. See <see cref="MultiplyMod"/>.
    /// </summary>
    internal static IntegerModP SquareMod(IntegerModP a)
    {
        MontgomeryContext context = MontgomeryContext.Current;
        int s = context.LimbCount;

        Span<ulong> limbs = s <= MaxStackAllocLimbs ? stackalloc ulong[MaxStackAllocLimbs] : new ulong[s];
        limbs = limbs[..s];

        context.ToMontgomery(a.ToBigInteger(), limbs);
        context.Square(limbs, limbs);

        return new IntegerModP(context.FromMontgomery(limbs));
    }

    /// <summary>
    /// Converts into Montgomery form and straight back out, for tests that the representation is
    /// lossless independently of any arithmetic performed in it.
    /// </summary>
    internal static IntegerModP RoundTrip(IntegerModP a)
    {
        MontgomeryContext context = MontgomeryContext.Current;
        int s = context.LimbCount;

        Span<ulong> limbs = s <= MaxStackAllocLimbs ? stackalloc ulong[MaxStackAllocLimbs] : new ulong[s];
        limbs = limbs[..s];

        context.ToMontgomery(a.ToBigInteger(), limbs);
        return new IntegerModP(context.FromMontgomery(limbs));
    }

    /// <summary>
    /// Table-free windowed square-and-multiply over Montgomery limbs, writing the Montgomery-form
    /// result into <paramref name="result"/>.
    ///
    /// The multiplication count does not depend on the exponent: every window performs its squarings
    /// and its multiply even when the window digit is zero, and there is no shortcut past leading
    /// zero digits. Skipping them would save under 5% while making the operation count a function of
    /// a secret nonce, which is a trade this code should not make. Table lookups are still indexed by
    /// exponent digits, so this is not fully constant-time against an adversary measuring cache
    /// behaviour; neither is the BigInteger.ModPow path it replaces.
    /// </summary>
    internal static void PowInto(BigInteger basis, ReadOnlySpan<byte> exponentBigEndian, MontgomeryContext context, Span<ulong> result)
    {
        int s = context.LimbCount;
        Span<ulong> montgomeryBasis = s <= MaxStackAllocLimbs ? stackalloc ulong[MaxStackAllocLimbs] : new ulong[s];
        montgomeryBasis = montgomeryBasis[..s];
        context.ToMontgomery(basis.Mod(context.Modulus), montgomeryBasis);

        PowMontgomeryInto(montgomeryBasis, exponentBigEndian, context, result);
    }

    /// <summary>
    /// <see cref="PowInto"/> for a basis that is already in Montgomery form, for callers that have
    /// computed it there and would otherwise convert out and straight back in.
    /// </summary>
    internal static void PowMontgomeryInto(ReadOnlySpan<ulong> montgomeryBasis, ReadOnlySpan<byte> exponentBigEndian, MontgomeryContext context, Span<ulong> result)
    {
        int s = context.LimbCount;

        // Both widths divide 8, so a byte always splits into a whole number of windows.
        int windowBits = exponentBigEndian.Length <= NarrowWindowMaxExponentBytes
            ? NarrowWindowBits
            : TableFreeWindowBits;
        int windowSize = 1 << windowBits;
        int windowsPerByte = 8 / windowBits;

        int windowLimbs = windowSize * s;
        Span<ulong> window = windowLimbs <= TableFreeWindowSize * MaxStackAllocLimbs
            ? stackalloc ulong[TableFreeWindowSize * MaxStackAllocLimbs]
            : new ulong[windowLimbs];
        window = window[..windowLimbs];

        // window[i] = basis^i in Montgomery form.
        context.One.CopyTo(window[..s]);
        montgomeryBasis.CopyTo(window.Slice(s, s));
        for (int i = 2; i < windowSize; i++)
        {
            context.Multiply(window.Slice((i - 1) * s, s), window.Slice(s, s), window.Slice(i * s, s));
        }

        Span<ulong> accumulator = s <= MaxStackAllocLimbs ? stackalloc ulong[MaxStackAllocLimbs] : new ulong[s];
        accumulator = accumulator[..s];
        context.One.CopyTo(accumulator);

        for (int i = 0; i < exponentBigEndian.Length; i++)
        {
            byte current = exponentBigEndian[i];

            // Most significant window of the byte first.
            for (int w = 0; w < windowsPerByte; w++)
            {
                int shift = 8 - windowBits * (w + 1);
                int digit = (current >> shift) & (windowSize - 1);

                for (int square = 0; square < windowBits; square++)
                {
                    context.Square(accumulator, accumulator);
                }

                context.Multiply(accumulator, window.Slice(digit * s, s), accumulator);
            }
        }

        accumulator.CopyTo(result);
    }
}
