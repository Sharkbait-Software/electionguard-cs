using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using System.Buffers;
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
/// square-and-multiply in Montgomery form. On hardware with AVX-512F that runs on
/// <see cref="Avx512Montgomery"/>, several times as fast as
/// <see cref="IntegerModP.PowModP(BigInteger, BigInteger)"/>; elsewhere, or for a p wider than 4096
/// bits, it runs on the scalar limbs of <see cref="MontgomeryContext"/>, roughly twice as fast. The
/// two give identical results, so which one ran is invisible to callers. If a caller has opted in by
/// precomputing a table for the base via <see cref="PowRadixRegistry"/>, that is used instead and is
/// roughly thirty times as fast. Note 3.5 predicts "an order of magnitude or more"; both halves of
/// the note, the table and the Montgomery form, are needed to get there.
///
/// <see cref="PowModPVariableTime(BigInteger, ReadOnlySpan{IntegerModQ}, Span{IntegerModP})"/> is
/// the one exception to this class's exponent-independent operation count: a verifier-only path for
/// raising one base to several public exponents, and never to be used with a secret.
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
    internal const int TableFreeWindowBits = 4;

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
    internal const int NarrowWindowMaxExponentBytes = 4;

    internal const int NarrowWindowBits = 1;

    /// <summary>Buffers longer than this are heap-allocated rather than stack-allocated.</summary>
    private const int MaxStackAllocLimbs = 80;

    /// <summary>
    /// Width an <see cref="IntegerModQ"/> exponent is always padded to, as
    /// <see cref="IntegerModQ.ToByteArray"/> does. The padding is load-bearing: it puts every element
    /// of Z_q, however small its value, on the 4-bit window, so the operation count of an
    /// exponentiation by a secret nonce does not reveal anything about its magnitude.
    /// </summary>
    private const int ZqExponentBytes = 32;

    /// <summary>BigInteger exponents up to this many bytes are serialized on the stack.</summary>
    private const int MaxStackAllocExponentBytes = 64;

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

        Span<byte> bytes = stackalloc byte[ZqExponentBytes];
        if (!TryWriteBigEndian(exponent.ToBigInteger(), bytes, padToLength: true, out _))
        {
            // Only reachable under a non-spec q wider than 256 bits; ToByteArray reports it.
            return PowModPTableFree(basis, exponent.ToByteArray());
        }

        return PowModPTableFree(basis, bytes);
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
    /// The table-free Montgomery path still applies, AVX-512 included, so these calls are as fast as
    /// the table-free <see cref="PowModP(BigInteger, IntegerModQ)"/>.
    /// </summary>
    public static IntegerModP PowModP(BigInteger basis, BigInteger exponent)
    {
        if (exponent.Sign < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(exponent), exponent, "Exponent must not be negative.");
        }

        Span<byte> bytes = stackalloc byte[MaxStackAllocExponentBytes];
        if (!TryWriteBigEndian(exponent, bytes, padToLength: false, out int written))
        {
            return PowModPTableFree(basis, exponent.ToByteArray(isUnsigned: true, isBigEndian: true));
        }

        return PowModPTableFree(basis, bytes[..written]);
    }

    /// <summary>
    /// Largest Yao window considered by <see cref="ChooseSharedSquaringWindowBits"/>. Above this the
    /// 2^w - 1 bucket-combining multiplies dominate for any exponent size this library uses, and it
    /// keeps every digit within two bytes of the exponent.
    /// </summary>
    private const int MaxSharedSquaringWindowBits = 8;

    /// <summary>
    /// Cost of a squaring relative to a multiply on <see cref="MontgomeryContext"/>: its SOS squaring
    /// does s(s+1)/2 + s^2 limb products against CIOS's 2s^2, about three quarters at 64 limbs.
    /// <see cref="Avx512Montgomery"/> has no squaring shortcut, so there it is 1.
    /// </summary>
    private const double ScalarSquareCost = 0.75;

    private const double Avx512SquareCost = 1.0;

    /// <summary>
    /// Single-value buffers of the shared-squaring path are stack-allocated up to this width, which
    /// covers both representations of the spec's p: 64 scalar limbs or 144 AVX-512 digits.
    /// </summary>
    private const int MaxStackAllocWidth = Avx512Montgomery.Lanes;

    /// <summary>Digit buffers of the shared-squaring path longer than this go on the heap.</summary>
    private const int MaxStackAllocDigits = 1024;

    /// <summary>
    /// Computes basis^exponents[k] mod p for every k, sharing one squaring chain across all of them.
    ///
    /// VARIABLE TIME. VERIFIER ONLY. FOR PUBLIC EXPONENTS ONLY. This exists for the verifier, where
    /// the exponents are proof challenges published in the election record (Verifications 6 and 7
    /// raise each selection or contest ciphertext component to every challenge c_j of its range
    /// proof). The work done here depends on the exponents' bit lengths and on which of their digits
    /// are zero or equal, so it must never be handed a secret: encryption, proof generation, key
    /// generation and decryption keep using <see cref="PowModP(BigInteger, IntegerModQ)"/>, whose
    /// operation count is independent of the exponent, and nothing under BallotEncryption,
    /// KeyGeneration or Tally may call this.
    ///
    /// Raising one base to m exponents with the table-free window costs m full squaring chains
    /// (256 squarings each for a 256-bit exponent). This instead uses Yao's method, the fixed-base
    /// algorithm of Brickell, Gordon, McCurley and Wilson with a table built on the fly: write each
    /// exponent e in base 2^w as sum d_i 2^(w i), compute x_i = basis^(2^(w i)) once (about 252
    /// squarings in total at w = 4, shared by every exponent), and then evaluate
    ///
    ///   basis^e = prod_{d = 1}^{2^w - 1} ( prod_{i : d_i = d} x_i )^d
    ///
    /// with the running-product trick: walking d downward, B accumulates the x_i whose digit is d
    /// and A multiplies in B after every step, so each x_i ends up raised to its own digit. That is
    /// one multiply per non-zero digit plus 2^w - 1 to combine, about 75 multiplies per 256-bit
    /// exponent at w = 4 and no squarings at all. For the m = 2 of a selection limit of 1 that is
    /// 252 squarings + ~150 multiplies per base, against 512 squarings + ~158 multiplies separately.
    ///
    /// On hardware with AVX-512F the whole computation stays in <see cref="Avx512Montgomery"/>'s
    /// representation: the base is converted in once, the chain and the combines use its multiply,
    /// and each result is converted out once. Elsewhere it runs on <see cref="MontgomeryContext"/>.
    /// The results are identical either way. Nothing is allocated but the results themselves and,
    /// for the chain, a buffer rented from <see cref="ArrayPool{T}.Shared"/>; there is no shared
    /// scratch state, so this is safe to call from many threads at once.
    ///
    /// A basis with a registered <see cref="PowRadix"/> table is routed to that table instead,
    /// exponent by exponent, which is cheaper still.
    /// </summary>
    /// <param name="basis">The common base. Reduced mod p.</param>
    /// <param name="exponents">The public exponents, each an element of Z_q.</param>
    /// <param name="results">Receives basis^exponents[k] at index k; must be as long as
    /// <paramref name="exponents"/>.</param>
    public static void PowModPVariableTime(BigInteger basis, ReadOnlySpan<IntegerModQ> exponents, Span<IntegerModP> results)
    {
        PowModPVariableTime(basis, exponents, results, allowAvx512: true);
    }

    /// <summary>
    /// <see cref="PowModPVariableTime(BigInteger, ReadOnlySpan{IntegerModQ}, Span{IntegerModP})"/>
    /// with the AVX-512 engine optionally ruled out, so that tests can check the scalar path on
    /// hardware that would otherwise never take it.
    /// </summary>
    internal static void PowModPVariableTime(BigInteger basis, ReadOnlySpan<IntegerModQ> exponents, Span<IntegerModP> results, bool allowAvx512)
    {
        if (results.Length != exponents.Length)
        {
            throw new ArgumentException("There must be exactly one result slot per exponent.", nameof(results));
        }

        if (exponents.IsEmpty)
        {
            return;
        }

        if (PowRadixRegistry.TryGet(basis, out PowRadix radix))
        {
            for (int k = 0; k < exponents.Length; k++)
            {
                results[k] = radix.Pow(exponents[k]);
            }

            return;
        }

        if (MaxExponentBits(exponents) == 0)
        {
            // Every exponent is zero, and basis^0 = 1 for every basis, including 0.
            results.Fill(new IntegerModP(BigInteger.One));
            return;
        }

        if (allowAvx512 && Avx512Montgomery.TryGetCurrent(out Avx512Montgomery engine))
        {
            PowVariableTimeToResidues(basis, exponents, results, new Avx512MontgomeryArithmetic(engine));
        }
        else
        {
            PowVariableTimeToResidues(basis, exponents, results, new ScalarMontgomeryArithmetic(MontgomeryContext.Current));
        }
    }

    /// <summary>
    /// The shared-squaring exponentiation, converted out of Montgomery form into
    /// <paramref name="results"/>. The Montgomery-form results go through a buffer rented from
    /// <see cref="ArrayPool{T}.Shared"/>, so nothing is allocated but the results themselves.
    /// </summary>
    private static void PowVariableTimeToResidues<TArithmetic>(
        BigInteger basis,
        ReadOnlySpan<IntegerModQ> exponents,
        Span<IntegerModP> results,
        TArithmetic arithmetic)
        where TArithmetic : struct, IMontgomeryArithmetic
    {
        int s = arithmetic.Width;
        ulong[] montgomeryArray = ArrayPool<ulong>.Shared.Rent(exponents.Length * s);
        try
        {
            Span<ulong> montgomery = montgomeryArray.AsSpan(0, exponents.Length * s);
            PowVariableTimeMontgomery(basis, exponents, montgomery, arithmetic);
            for (int k = 0; k < exponents.Length; k++)
            {
                results[k] = new IntegerModP(arithmetic.FromMontgomery(montgomery.Slice(k * s, s)));
            }
        }
        finally
        {
            ArrayPool<ulong>.Shared.Return(montgomeryArray);
        }
    }

    /// <summary>
    /// <see cref="PowModPVariableTime(BigInteger, ReadOnlySpan{IntegerModQ}, Span{IntegerModP})"/>
    /// leaving each result in Montgomery form, in <paramref name="arithmetic"/>'s representation, at
    /// <c>results[k * Width .. (k + 1) * Width)</c>, for callers that will multiply the powers by
    /// something else in that representation before converting out once (the range-proof checks of
    /// Verifications 6 and 7). The same VARIABLE TIME, PUBLIC EXPONENTS ONLY restriction applies.
    ///
    /// Unlike the public entry point this never consults <see cref="PowRadixRegistry"/>: a table's
    /// representation is fixed when it is built and need not match <paramref name="arithmetic"/>,
    /// and the bases this serves, ciphertext components, never have one.
    /// </summary>
    internal static void PowVariableTimeMontgomery<TArithmetic>(
        BigInteger basis,
        ReadOnlySpan<IntegerModQ> exponents,
        Span<ulong> results,
        TArithmetic arithmetic)
        where TArithmetic : struct, IMontgomeryArithmetic
    {
        int s = arithmetic.Width;
        if (results.Length < exponents.Length * s)
        {
            throw new ArgumentException("There must be exactly one result slot per exponent.", nameof(results));
        }

        if (exponents.IsEmpty)
        {
            return;
        }

        long maxBits = MaxExponentBits(exponents);
        if (maxBits == 0)
        {
            // Every exponent is zero, and basis^0 = 1 for every basis, including 0.
            for (int k = 0; k < exponents.Length; k++)
            {
                arithmetic.One.CopyTo(results.Slice(k * s, s));
            }

            return;
        }

        // An IntegerModP is already reduced; only a raw BigInteger basis can need it, and reducing
        // unconditionally would allocate a copy every time.
        BigInteger p = EGParameters.P;
        BigInteger reduced = basis.Sign >= 0 && basis < p ? basis : basis.Mod(p);

        // typeof comparisons on a struct type parameter are JIT-time constants.
        double squareCost = typeof(TArithmetic) == typeof(Avx512MontgomeryArithmetic) ? Avx512SquareCost : ScalarSquareCost;
        int windowBits = ChooseSharedSquaringWindowBits(maxBits, exponents.Length, squareCost);
        PowVariableTimeCore(reduced, exponents, results, maxBits, windowBits, arithmetic);
    }

    private static long MaxExponentBits(ReadOnlySpan<IntegerModQ> exponents)
    {
        long maxBits = 0;
        for (int k = 0; k < exponents.Length; k++)
        {
            maxBits = Math.Max(maxBits, exponents[k].ToBigInteger().GetBitLength());
        }

        return maxBits;
    }

    /// <summary>
    /// The Yao evaluation behind <see cref="PowModPVariableTime(BigInteger, ReadOnlySpan{IntegerModQ}, Span{IntegerModP})"/>,
    /// generic over the representation so that each engine gets its own compiled copy.
    /// <paramref name="basis"/> is already in [0, p) and at least one exponent is non-zero. Writes
    /// each Montgomery-form result to its <see cref="IMontgomeryArithmetic.Width"/>-word slot of
    /// <paramref name="results"/>.
    /// </summary>
    private static void PowVariableTimeCore<TArithmetic>(
        BigInteger basis,
        ReadOnlySpan<IntegerModQ> exponents,
        Span<ulong> results,
        long maxBits,
        int windowBits,
        TArithmetic arithmetic)
        where TArithmetic : struct, IMontgomeryArithmetic
    {
        int s = arithmetic.Width;
        int digitMask = (1 << windowBits) - 1;
        int digitCount = (int)((maxBits + windowBits - 1) / windowBits);

        // Rented arrays hold stale data. That is harmless here: row 0 is written by ToMontgomery and
        // every later row by the squaring that derives it, each before anything reads it.
        ulong[] chainArray = ArrayPool<ulong>.Shared.Rent(digitCount * s);
        try
        {
            Span<ulong> chain = chainArray.AsSpan(0, digitCount * s);

            // chain[i] = basis^(2^(w i)) in Montgomery form: the only squarings, done once for all
            // exponents.
            arithmetic.ToMontgomery(basis, chain[..s]);
            for (int i = 1; i < digitCount; i++)
            {
                Span<ulong> next = chain.Slice(i * s, s);
                arithmetic.Square(chain.Slice((i - 1) * s, s), next);
                for (int square = 1; square < windowBits; square++)
                {
                    arithmetic.Square(next, next);
                }
            }

            Span<ulong> bucket = s <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[s];
            Span<ulong> accumulator = s <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[s];
            bucket = bucket[..s];
            accumulator = accumulator[..s];

            Span<byte> digits = digitCount <= MaxStackAllocDigits ? stackalloc byte[MaxStackAllocDigits] : new byte[digitCount];
            digits = digits[..digitCount];

            Span<byte> exponentBuffer = stackalloc byte[ZqExponentBytes];

            for (int k = 0; k < exponents.Length; k++)
            {
                BigInteger exponent = exponents[k].ToBigInteger();
                ReadOnlySpan<byte> bytes = TryWriteBigEndian(exponent, exponentBuffer, padToLength: true, out _)
                    ? exponentBuffer
                    // Only reachable under a non-spec q wider than 256 bits.
                    : exponent.ToByteArray(isUnsigned: true, isBigEndian: true);
                ReadDigits(bytes, windowBits, digits);

                // While either running product is still 1, the first factor is copied in rather
                // than multiplied, saving a multiply each. Both are branches on the exponent's
                // digits, which is fine only because the exponent is public.
                bool bucketIsOne = true;
                bool accumulatorIsOne = true;
                for (int d = digitMask; d >= 1; d--)
                {
                    for (int i = 0; i < digitCount; i++)
                    {
                        if (digits[i] != d)
                        {
                            continue;
                        }

                        ReadOnlySpan<ulong> power = chain.Slice(i * s, s);
                        if (bucketIsOne)
                        {
                            power.CopyTo(bucket);
                            bucketIsOne = false;
                        }
                        else
                        {
                            arithmetic.Multiply(bucket, power, bucket);
                        }
                    }

                    if (bucketIsOne)
                    {
                        continue;
                    }

                    if (accumulatorIsOne)
                    {
                        bucket.CopyTo(accumulator);
                        accumulatorIsOne = false;
                    }
                    else
                    {
                        arithmetic.Multiply(accumulator, bucket, accumulator);
                    }
                }

                Span<ulong> result = results.Slice(k * s, s);
                if (accumulatorIsOne)
                {
                    arithmetic.One.CopyTo(result);
                }
                else
                {
                    accumulator.CopyTo(result);
                }
            }
        }
        finally
        {
            ArrayPool<ulong>.Shared.Return(chainArray);
        }
    }

    /// <summary>
    /// Splits a big-endian exponent into base-2^<paramref name="windowBits"/> digits, least
    /// significant first, filling all of <paramref name="digits"/>: digits past the exponent's own
    /// length read as zero. A digit may straddle a byte boundary for widths that do not divide 8,
    /// so each is assembled from up to two bytes; widths above 8 are never chosen.
    /// </summary>
    private static void ReadDigits(ReadOnlySpan<byte> exponentBigEndian, int windowBits, Span<byte> digits)
    {
        int mask = (1 << windowBits) - 1;
        int last = exponentBigEndian.Length - 1;
        for (int i = 0; i < digits.Length; i++)
        {
            int bit = i * windowBits;
            int index = last - (bit >> 3);
            int offset = bit & 7;
            if (index < 0)
            {
                digits[i] = 0;
                continue;
            }

            int value = exponentBigEndian[index] >> offset;
            if (offset + windowBits > 8 && index > 0)
            {
                value |= exponentBigEndian[index - 1] << (8 - offset);
            }

            digits[i] = (byte)(value & mask);
        }
    }

    /// <summary>
    /// The Yao window that minimises the expected cost, in multiplies, of raising one base to
    /// <paramref name="exponentCount"/> exponents of up to <paramref name="exponentBits"/> bits:
    /// the shared chain's (ceil(bits / w) - 1) * w squarings, each costing
    /// <paramref name="squareCost"/> multiplies, plus per exponent one multiply per non-zero digit
    /// (h (1 - 2^-w) on average for h = ceil(bits / w) digits) and 2^w - 1 to combine the buckets.
    ///
    /// For the spec's 256-bit q this lands on w = 4 whatever the squaring cost and the exponent
    /// count: the chain is 248 to 255 squarings for every w from 3 to 8, while the per-exponent term
    /// is about 75 multiplies at w = 4 against 81 at w = 5 and 82 at w = 3. So the AVX-512 engine,
    /// where a square costs a full multiply, and the scalar one, where it costs about three
    /// quarters of one, choose the same window.
    /// </summary>
    internal static int ChooseSharedSquaringWindowBits(long exponentBits, int exponentCount, double squareCost)
    {
        int best = 1;
        double bestCost = double.MaxValue;
        for (int w = 1; w <= MaxSharedSquaringWindowBits; w++)
        {
            long digitCount = (exponentBits + w - 1) / w;
            double chain = squareCost * (digitCount - 1) * w;
            double perExponent = digitCount * (1 - Math.Pow(2, -w)) + ((1 << w) - 1);
            double cost = chain + exponentCount * perExponent;
            if (cost < bestCost)
            {
                bestCost = cost;
                best = w;
            }
        }

        return best;
    }

    /// <summary>
    /// Writes a non-negative value big-endian into <paramref name="destination"/> without allocating:
    /// right-aligned and zero-padded to the whole span, or into its first <paramref name="written"/>
    /// bytes. False if it does not fit.
    /// </summary>
    private static bool TryWriteBigEndian(BigInteger value, Span<byte> destination, bool padToLength, out int written)
    {
        int length = value.GetByteCount(isUnsigned: true);
        if (length > destination.Length)
        {
            written = 0;
            return false;
        }

        if (padToLength)
        {
            destination.Clear();
            destination = destination[(destination.Length - length)..];
        }

        return value.TryWriteBytes(destination, out written, isUnsigned: true, isBigEndian: true);
    }

    /// <summary>
    /// The table-free exponentiation, on <see cref="Avx512Montgomery"/> when the hardware and p allow
    /// it and on <see cref="MontgomeryContext"/> otherwise. On the AVX-512 path nothing is allocated
    /// but the result itself, which matters because verification runs this from many threads at once.
    /// </summary>
    private static IntegerModP PowModPTableFree(BigInteger basis, ReadOnlySpan<byte> exponentBigEndian)
    {
        if (Avx512Montgomery.TryGetCurrent(out Avx512Montgomery engine))
        {
            // An IntegerModP is already reduced; only a raw BigInteger basis can need it, and
            // reducing unconditionally would allocate a copy every time.
            BigInteger p = engine.Modulus;
            BigInteger reduced = basis.Sign >= 0 && basis < p ? basis : basis.Mod(p);

            Span<ulong> montgomery = stackalloc ulong[Avx512Montgomery.Lanes];
            engine.PowInto(reduced, exponentBigEndian, montgomery);
            return new IntegerModP(engine.FromMontgomery(montgomery));
        }

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
