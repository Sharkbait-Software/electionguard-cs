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
    /// Largest sliding window considered by <see cref="ChooseSlidingWindowBits"/>. Above this the
    /// bucket-combining multiplies dominate for any exponent size this library uses, and it keeps
    /// every digit within a byte.
    /// </summary>
    private const int MaxSlidingWindowBits = 8;

    /// <summary>
    /// Most set bits c may have, for q = 2^t - c, for the membership check of
    /// <see cref="PowVariableTimeMontgomeryCheckingMembership"/>: each costs a multiply per base.
    /// The spec's c = 189 has six.
    /// </summary>
    private const int MaxMembershipRemainderBits = 16;

    /// <summary>
    /// Single-value buffers of the shared-squaring path are stack-allocated up to this width, which
    /// covers both representations of the spec's p: 64 scalar limbs or 80 AVX-512 digits.
    /// </summary>
    private const int MaxStackAllocWidth = Avx512Montgomery.Lanes;

    /// <summary>Digit buffers of the shared-squaring path longer than this are rented rather than stack-allocated.</summary>
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
    /// algorithm of Brickell, Gordon, McCurley and Wilson with the table built on the fly: walk the
    /// chain x_i = basis^(2^i) once (about 255 squarings, shared by every exponent), and for each
    /// exponent multiply each x_i into a bucket chosen by the exponent's digit at bit i, then raise
    /// each bucket to its digit by a running product:
    ///
    ///   basis^e = prod_d ( prod_{i : d_i = d} x_i )^d
    ///
    /// The digits are right-to-left sliding windows, odd and at most w bits, so a 256-bit exponent
    /// has about 256 / (w + 1) of them. At w = 4 that is about 51 multiplies to fill the buckets and
    /// 16 to combine them, and no squarings at all. For the m = 2 of a selection limit of 1 that is
    /// about 255 squarings + ~135 multiplies per base, against 512 squarings + ~158 multiplies
    /// separately, and about 7% fewer operations than the fixed 4-bit windows this used before.
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

        PowVariableTimeCore(reduced, exponents, results, maxBits, ChooseSlidingWindowBits(maxBits), arithmetic, membershipShape: null);
    }

    /// <summary>
    /// <see cref="PowVariableTimeMontgomery"/>, also deciding, exactly, whether
    /// <paramref name="basis"/> lies in Z_p^r: true when 0 &lt; basis &lt; p and basis^q = 1. The
    /// subgroup test rides on the squaring chain the exponentiation walks anyway (see
    /// <see cref="PowVariableTimeCore"/>), so it costs a handful of multiplies rather than the
    /// exponentiation by q it replaces. Only available when q = 2^t - c for a c with few set bits;
    /// callers check <see cref="TryGetChainMembershipShape"/> first. The same VARIABLE TIME, PUBLIC
    /// EXPONENTS ONLY restriction applies to <paramref name="exponents"/>; the basis's membership is
    /// decided by a comparison whose outcome is the public result.
    /// </summary>
    internal static bool PowVariableTimeMontgomeryCheckingMembership<TArithmetic>(
        IntegerModP basis,
        ReadOnlySpan<IntegerModQ> exponents,
        Span<ulong> results,
        TArithmetic arithmetic)
        where TArithmetic : struct, IMontgomeryArithmetic
    {
        if (results.Length < exponents.Length * arithmetic.Width)
        {
            throw new ArgumentException("There must be exactly one result slot per exponent.", nameof(results));
        }

        if (!TryGetChainMembershipShape(out ChainMembershipShape shape))
        {
            throw new InvalidOperationException("The active q does not have the shape the chain membership check needs.");
        }

        BigInteger value = basis.ToBigInteger();
        long maxBits = MaxExponentBits(exponents);
        bool congruent = PowVariableTimeCore(value, exponents, results, maxBits, ChooseSlidingWindowBits(Math.Max(1, maxBits)), arithmetic, shape);

        // basis = 0 satisfies 0^(2^t) = 0^c too; it is not in the group at all.
        return congruent && value.Sign > 0 && value < EGParameters.P;
    }

    /// <summary>
    /// q written as 2^<see cref="PowerOfTwo"/> - <see cref="Remainder"/>, with t the bit length of q,
    /// for the chain membership check.
    /// </summary>
    internal readonly record struct ChainMembershipShape(int PowerOfTwo, ulong Remainder);

    private sealed record MembershipShapeEntry(BigInteger Q, ChainMembershipShape? Shape);

    private static MembershipShapeEntry? _membershipShape;

    /// <summary>
    /// Whether the active q is 2^t - c for a c with at most <see cref="MaxMembershipRemainderBits"/>
    /// set bits, which the chain membership check needs; the spec's q = 2^256 - 189 is. Recomputed
    /// only when <see cref="EGParameters"/> is pointed at a different q.
    /// </summary>
    internal static bool TryGetChainMembershipShape(out ChainMembershipShape shape)
    {
        BigInteger q = EGParameters.Q;
        MembershipShapeEntry? entry = _membershipShape;
        if (entry is null || entry.Q != q)
        {
            entry = new MembershipShapeEntry(q, ComputeMembershipShape(q));
            Volatile.Write(ref _membershipShape, entry);
        }

        shape = entry.Shape.GetValueOrDefault();
        return entry.Shape.HasValue;
    }

    private static ChainMembershipShape? ComputeMembershipShape(BigInteger q)
    {
        if (q.Sign <= 0)
        {
            return null;
        }

        int t = (int)q.GetBitLength();
        BigInteger c = (BigInteger.One << t) - q;
        if (c.Sign <= 0 || c.GetBitLength() > 63 || BitOperations.PopCount((ulong)c) > MaxMembershipRemainderBits)
        {
            return null;
        }

        return new ChainMembershipShape(t, (ulong)c);
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
    /// The evaluation behind <see cref="PowModPVariableTime(BigInteger, ReadOnlySpan{IntegerModQ}, Span{IntegerModP})"/>,
    /// generic over the representation so that each engine gets its own compiled copy.
    /// <paramref name="basis"/> is already in [0, p). Writes each Montgomery-form result to its
    /// <see cref="IMontgomeryArithmetic.Width"/>-word slot of <paramref name="results"/>.
    ///
    /// Yao's method with right-to-left sliding windows. Each exponent is recoded, from its least
    /// significant bit up, into odd digits d of at most <paramref name="windowBits"/> bits, each at
    /// the position i of its lowest bit, so e = sum d * 2^i: about bits / (w + 1) digits rather than
    /// the bits / w of fixed windows. The chain basis^(2^i) is then walked once, from i = 0 up to the
    /// highest digit position, and each power is multiplied into the bucket of every exponent with a
    /// digit at that position; bucket d of an exponent ends up as the product of the powers carrying
    /// digit d. Nothing of the chain is kept but the current power. Finally each exponent's buckets
    /// are combined as prod B_d^d over the 2^(w - 1) odd d. Writing d = 2m + 1, that is
    /// (prod B_d^m)^2 * prod B_d; walking m downward, A gathers the buckets and R multiplies in A
    /// after every step but the last, which leaves R = prod B_d^m and A = prod B_d.
    ///
    /// With <paramref name="membershipShape"/> set, the same walk also decides whether the basis
    /// lies in the order-q subgroup: q = 2^t - c, so for basis x invertible mod p, x^q = 1 exactly
    /// when x^(2^t) = x^c. The walk is carried on to i = t, x^c is gathered from the chain powers at
    /// c's set bits like one more exponent, and the two are compared. For the spec's
    /// q = 2^256 - 189 that is at most a few more squarings, five multiplies and a comparison. The
    /// basis 0 also satisfies the identity, so excluding it is the caller's job.
    /// </summary>
    private static bool PowVariableTimeCore<TArithmetic>(
        BigInteger basis,
        ReadOnlySpan<IntegerModQ> exponents,
        Span<ulong> results,
        long maxBits,
        int windowBits,
        TArithmetic arithmetic,
        ChainMembershipShape? membershipShape)
        where TArithmetic : struct, IMontgomeryArithmetic
    {
        int s = arithmetic.Width;
        int exponentCount = exponents.Length;
        int positions = (int)maxBits;
        int bucketsPerExponent = 1 << (windowBits - 1);
        int bucketCount = exponentCount * bucketsPerExponent;

        // digitAt[k * positions + i] is exponent k's odd digit at bit i, or 0.
        int digitLength = exponentCount * positions;
        byte[]? rentedDigits = digitLength > MaxStackAllocDigits ? ArrayPool<byte>.Shared.Rent(digitLength) : null;
        Span<byte> digitAt = rentedDigits is null ? stackalloc byte[MaxStackAllocDigits] : rentedDigits;
        digitAt = digitAt[..digitLength];

        Span<byte> exponentBuffer = stackalloc byte[ZqExponentBytes];
        int lastPosition = -1;
        for (int k = 0; k < exponentCount; k++)
        {
            BigInteger exponent = exponents[k].ToBigInteger();
            ReadOnlySpan<byte> bytes = TryWriteBigEndian(exponent, exponentBuffer, padToLength: true, out _)
                ? exponentBuffer
                // Only reachable under a non-spec q wider than 256 bits.
                : exponent.ToByteArray(isUnsigned: true, isBigEndian: true);
            lastPosition = Math.Max(lastPosition, RecodeSlidingWindow(bytes, windowBits, digitAt.Slice(k * positions, positions)));
        }

        int chainEnd = lastPosition;
        if (membershipShape is { } shape)
        {
            chainEnd = Math.Max(chainEnd, shape.PowerOfTwo);
        }

        // Rented arrays hold stale data, which is harmless: a bucket is only read once its flag says
        // it has been written.
        ulong[] bucketArray = ArrayPool<ulong>.Shared.Rent(Math.Max(1, bucketCount * s));
        bool[] bucketFilledArray = ArrayPool<bool>.Shared.Rent(Math.Max(1, bucketCount));
        try
        {
            Span<ulong> buckets = bucketArray.AsSpan(0, bucketCount * s);
            Span<bool> bucketFilled = bucketFilledArray.AsSpan(0, bucketCount);
            bucketFilled.Clear();

            Span<ulong> power = s <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[s];
            Span<ulong> residue = s <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[s];
            power = power[..s];
            residue = residue[..s];
            bool residueFilled = false;
            bool isMember = false;

            arithmetic.ToMontgomery(basis, power);
            for (int i = 0; ; i++)
            {
                if (i < positions)
                {
                    for (int k = 0; k < exponentCount; k++)
                    {
                        int digit = digitAt[k * positions + i];
                        if (digit != 0)
                        {
                            // Digits are odd, so digit >> 1 indexes the odd values 1, 3, 5, ...
                            int bucket = k * bucketsPerExponent + (digit >> 1);
                            MultiplyInto(arithmetic, buckets.Slice(bucket * s, s), ref bucketFilled[bucket], power);
                        }
                    }
                }

                if (membershipShape is { } check)
                {
                    if (i < 64 && ((check.Remainder >> i) & 1) != 0)
                    {
                        MultiplyInto(arithmetic, residue, ref residueFilled, power);
                    }

                    if (i == check.PowerOfTwo)
                    {
                        // power = basis^(2^t), residue = basis^c, and c > 0, so residue is filled.
                        isMember = arithmetic.AreCongruent(power, residue);
                    }
                }

                if (i >= chainEnd)
                {
                    break;
                }

                arithmetic.Square(power, power);
            }

            Span<ulong> gathered = s <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[s];
            Span<ulong> weighted = s <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[s];
            gathered = gathered[..s];
            weighted = weighted[..s];
            for (int k = 0; k < exponentCount; k++)
            {
                // While a running product is still 1 the first factor is copied in rather than
                // multiplied. These are branches on the exponent's digits, which is fine only because
                // the exponent is public.
                bool gatheredFilled = false;
                bool weightedFilled = false;
                for (int m = bucketsPerExponent - 1; m >= 0; m--)
                {
                    int bucket = k * bucketsPerExponent + m;
                    if (bucketFilled[bucket])
                    {
                        MultiplyInto(arithmetic, gathered, ref gatheredFilled, buckets.Slice(bucket * s, s));
                    }

                    if (m >= 1 && gatheredFilled)
                    {
                        MultiplyInto(arithmetic, weighted, ref weightedFilled, gathered);
                    }
                }

                Span<ulong> result = results.Slice(k * s, s);
                if (!gatheredFilled)
                {
                    // A zero exponent: no digits at all.
                    arithmetic.One.CopyTo(result);
                }
                else if (!weightedFilled)
                {
                    gathered.CopyTo(result);
                }
                else
                {
                    arithmetic.Square(weighted, weighted);
                    arithmetic.Multiply(weighted, gathered, result);
                }
            }

            return isMember;
        }
        finally
        {
            ArrayPool<ulong>.Shared.Return(bucketArray);
            ArrayPool<bool>.Shared.Return(bucketFilledArray);
            if (rentedDigits is not null)
            {
                ArrayPool<byte>.Shared.Return(rentedDigits);
            }
        }
    }

    /// <summary>
    /// accumulator *= factor, or accumulator = factor while <paramref name="filled"/> says the
    /// accumulator still stands for 1, which saves the multiply.
    /// </summary>
    private static void MultiplyInto<TArithmetic>(TArithmetic arithmetic, Span<ulong> accumulator, ref bool filled, ReadOnlySpan<ulong> factor)
        where TArithmetic : struct, IMontgomeryArithmetic
    {
        if (filled)
        {
            arithmetic.Multiply(accumulator, factor, accumulator);
        }
        else
        {
            factor.CopyTo(accumulator);
            filled = true;
        }
    }

    /// <summary>
    /// Recodes a big-endian exponent into right-to-left sliding-window digits: scanning up from bit
    /// 0, every set bit starts a digit made of it and the <paramref name="windowBits"/> - 1 bits
    /// above it, so each digit is odd and below 2^windowBits, and the scan resumes past the window.
    /// <paramref name="digitAt"/>[i] receives the digit starting at bit i, or 0; it covers the
    /// exponent's bit length, and bits a window reaches beyond it read as zero. Returns the highest
    /// position holding a digit, or -1 for a zero exponent.
    /// </summary>
    internal static int RecodeSlidingWindow(ReadOnlySpan<byte> exponentBigEndian, int windowBits, Span<byte> digitAt)
    {
        digitAt.Clear();
        int totalBits = exponentBigEndian.Length * 8;
        int last = -1;
        int i = 0;
        while (i < digitAt.Length)
        {
            if (Bit(exponentBigEndian, i) == 0)
            {
                i++;
                continue;
            }

            int digit = 0;
            for (int j = 0; j < windowBits && i + j < totalBits; j++)
            {
                digit |= Bit(exponentBigEndian, i + j) << j;
            }

            digitAt[i] = (byte)digit;
            last = i;
            i += windowBits;
        }

        return last;
    }

    private static int Bit(ReadOnlySpan<byte> bigEndian, int index)
    {
        return (bigEndian[bigEndian.Length - 1 - (index >> 3)] >> (index & 7)) & 1;
    }

    /// <summary>
    /// The sliding window that minimises the expected cost, in multiplies, of raising one base to
    /// exponents of up to <paramref name="exponentBits"/> bits: per exponent, one multiply per digit,
    /// about bits / (w + 1) of them, and about 2^w to combine its 2^(w - 1) buckets. The shared chain
    /// is about <paramref name="exponentBits"/> squarings whatever the window, so it does not enter
    /// the choice, and neither does the number of exponents, which scales every window's cost alike.
    ///
    /// For the spec's 256-bit q this is w = 4: about 51 + 16 multiplies per exponent, against 43 + 32
    /// at w = 5 and 64 + 8 at w = 3.
    /// </summary>
    internal static int ChooseSlidingWindowBits(long exponentBits)
    {
        int best = 1;
        double bestCost = double.MaxValue;
        for (int w = 1; w <= MaxSlidingWindowBits; w++)
        {
            double cost = exponentBits / (w + 1.0) + (1 << w);
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
