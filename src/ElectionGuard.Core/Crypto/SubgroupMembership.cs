using ElectionGuard.Core.Models;
using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;

namespace ElectionGuard.Core.Crypto;

/// <summary>
/// Membership tests for Z_p^r, the order-q subgroup of Z_p^* (§3.1.1), which Verifications 6.A and
/// 7.A require of every ciphertext component on a ballot.
///
/// The exact test, x^q mod p = 1, is a full exponentiation with no precomputed table, since the
/// base is different on every ballot. A ballot carries hundreds of such values, so these checks were
/// about a third of ballot verification. <see cref="IndexOfFirstNonMember"/> instead tests a whole
/// list at once, in two parts:
///
/// 1. The Jacobi symbol of each value. p - 1 = 2 * q * r', with q and r' odd primes, so every member
///    of the subgroup is a quadratic residue and has symbol 1. Any value whose symbol is not 1 is
///    therefore definitely not a member. This part is exact, and costs a binary GCD rather than an
///    exponentiation.
/// 2. A small-exponent batch test (Bellare, Garay and Rabin, "Fast batch verification for modular
///    exponentiation and digital signatures", 1998): pick independent uniform 128-bit exponents e_i
///    and check (prod x_i^e_i)^q = 1. Having passed part 1, every x_i lies in the quadratic residues,
///    a cyclic group of order q * r'. Write x_i = y_i * z_i with y_i of order dividing q and z_i of
///    order dividing r'. Raising the product to q kills every y_i, and because gcd(q, r') = 1 it
///    leaves 1 exactly when prod z_i^e_i = 1. If some z_k is not 1, then for any fixed choice of the
///    other exponents at most one residue of e_k modulo the prime r' satisfies that, and r' is far
///    larger than 2^128, so the test accepts a list containing a non-member with probability at most
///    2^-128.
///
/// Part 2 is why this is probabilistic, and its argument depends on the factorization of p - 1. It
/// holds for the spec's parameters (r = 2 * r' with r' a 3840-bit prime; a unit test pins this), but
/// nothing guarantees it for an arbitrary parameter set swapped in through
/// <see cref="EGParameters"/>, so for any other p and q this falls back to testing each value
/// exactly.
///
/// A list that fails the batch test is rescanned with the exact test, so a caller always learns
/// precisely which value is not a member. A list that is entirely valid never pays for that rescan,
/// and that is the case that has to be fast.
///
/// Part 2's arithmetic runs on <see cref="Avx512Montgomery"/> when the hardware has AVX-512F, and on
/// the scalar <see cref="MontgomeryContext"/> otherwise. The soundness argument above is about the
/// group, not the representation: both compute the same residues, the AVX-512 one merely holding
/// them redundantly in [0, 2p) until the final comparison with 1.
/// </summary>
public static class SubgroupMembership
{
    /// <summary>
    /// Bits in each random batch exponent, which is also the soundness level: a list containing a
    /// non-member passes with probability at most 2^-BatchExponentBits.
    /// </summary>
    internal const int BatchExponentBits = 128;

    /// <summary>Buffers longer than this are heap-allocated rather than stack-allocated.</summary>
    private const int MaxStackAllocLimbs = 80;

    /// <summary>
    /// The batch test's single-value buffers are stack-allocated up to this width, which covers both
    /// representations of the spec's p: 64 scalar limbs or 144 AVX-512 digits.
    /// </summary>
    private const int MaxStackAllocWidth = Avx512Montgomery.Lanes;

    /// <summary>q is serialized on the stack when it fits in this many bytes, which the spec's 32 do.</summary>
    private const int MaxStackAllocExponentBytes = 64;

    /// <summary>Lists this short gain nothing from batching over the exact test.</summary>
    private const int MinBatchSize = 2;

    private static readonly CryptographicParameters SpecParameters = new();

    /// <summary>
    /// Exact test: value is in Z_p^r when 0 &lt; value &lt; p and value^q mod p = 1.
    /// </summary>
    public static bool IsMember(IntegerModP value)
    {
        return value > 0
            && value < EGParameters.P
            && MontgomeryModP.PowModP(value, EGParameters.Q) == 1;
    }

    /// <summary>
    /// The index of the first value in <paramref name="values"/> that is not in Z_p^r, or -1 if all
    /// of them are. "First" is meaningful whatever the outcome of the batch test: a failing batch is
    /// rescanned in order with the exact test.
    /// </summary>
    public static int IndexOfFirstNonMember(IReadOnlyList<IntegerModP> values)
    {
        if (values.Count < MinBatchSize || !BatchingIsSoundForActiveParameters())
        {
            return IndexOfFirstNonMemberExact(values);
        }

        MontgomeryContext context = MontgomeryContext.Current;

        for (int i = 0; i < values.Count; i++)
        {
            if (values[i] <= 0 || values[i] >= EGParameters.P || Jacobi(values[i].ToBigInteger(), context) != 1)
            {
                // Exact: a non-residue, or zero, cannot be a member. Earlier values have only passed
                // their Jacobi check, though, so one of them may still be the first non-member.
                int earlier = IndexOfFirstNonMemberExact(values, i);
                return earlier >= 0 ? earlier : i;
            }
        }

        bool batchPassed = Avx512Montgomery.TryGetCurrent(out Avx512Montgomery engine)
            ? BatchTest(values, new Avx512MontgomeryArithmetic(engine))
            : BatchTest(values, new ScalarMontgomeryArithmetic(context));

        return batchPassed ? -1 : IndexOfFirstNonMemberExact(values);
    }

    /// <summary>
    /// Whether the active parameters are the spec's, whose p - 1 has the factorization the batch
    /// test's soundness argument relies on.
    /// </summary>
    internal static bool BatchingIsSoundForActiveParameters()
    {
        return EGParameters.P == SpecParameters.P && EGParameters.Q == SpecParameters.Q;
    }

    private static int IndexOfFirstNonMemberExact(IReadOnlyList<IntegerModP> values, int count = -1)
    {
        int end = count < 0 ? values.Count : count;
        for (int i = 0; i < end; i++)
        {
            if (!IsMember(values[i]))
            {
                return i;
            }
        }

        return -1;
    }

    /// <summary>
    /// Computes (prod values[i]^e_i)^q for fresh random 128-bit e_i and reports whether it is 1.
    ///
    /// The product is one multi-exponentiation using Pippenger's bucket method, which for n bases
    /// and c-bit windows costs about (128 / c) * (n + 2^(c+1)) multiplications plus 128 squarings,
    /// instead of the roughly 160 multiplications per base that separate 128-bit exponentiations
    /// would. Everything here is variable-time, which is fine: the values are public ballot data,
    /// and the exponents are this verifier's own coins, drawn after the ballot was fixed.
    ///
    /// Generic over the arithmetic (<see cref="IMontgomeryArithmetic"/>), with a struct constraint, so
    /// that the JIT compiles one copy per representation with the multiplications called directly
    /// rather than through an interface.
    /// </summary>
    private static bool BatchTest<TArithmetic>(IReadOnlyList<IntegerModP> values, TArithmetic arithmetic)
        where TArithmetic : struct, IMontgomeryArithmetic
    {
        int n = values.Count;
        int s = arithmetic.Width;
        int windowBits = ChooseWindowBits(n);
        int bucketCount = 1 << windowBits;
        int windows = (BatchExponentBits + windowBits - 1) / windowBits;
        UInt128 digitMask = (UInt128)(bucketCount - 1);

        ulong[] bases = ArrayPool<ulong>.Shared.Rent(n * s);
        ulong[] buckets = ArrayPool<ulong>.Shared.Rent(bucketCount * s);
        UInt128[] exponents = ArrayPool<UInt128>.Shared.Rent(n);
        byte[] randomArray = ArrayPool<byte>.Shared.Rent(n * (BatchExponentBits / 8));
        try
        {
            // A rented buffer rather than a fresh array. Every byte read below is overwritten here first.
            Span<byte> randomBytes = randomArray.AsSpan(0, n * (BatchExponentBits / 8));
            ElectionGuardRandom.Fill(randomBytes);
            for (int i = 0; i < n; i++)
            {
                ReadOnlySpan<byte> bytes = randomBytes.Slice(i * 16, 16);
                exponents[i] = new UInt128(
                    BinaryPrimitives.ReadUInt64LittleEndian(bytes[8..]),
                    BinaryPrimitives.ReadUInt64LittleEndian(bytes));

                arithmetic.ToMontgomery(values[i].ToBigInteger(), bases.AsSpan(i * s, s));
            }

            Span<bool> filled = stackalloc bool[bucketCount];

            Span<ulong> accumulator = s <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[s];
            Span<ulong> running = s <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[s];
            Span<ulong> total = s <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[s];
            accumulator = accumulator[..s];
            running = running[..s];
            total = total[..s];

            // "Empty" stands for the identity, so that no multiplication by one is ever performed.
            bool accumulatorEmpty = true;

            for (int window = windows - 1; window >= 0; window--)
            {
                if (!accumulatorEmpty)
                {
                    for (int square = 0; square < windowBits; square++)
                    {
                        arithmetic.Square(accumulator, accumulator);
                    }
                }

                // Sort each base into the bucket named by its digit in this window.
                filled.Clear();
                int shift = window * windowBits;
                for (int i = 0; i < n; i++)
                {
                    int digit = (int)((exponents[i] >> shift) & digitMask);
                    if (digit == 0)
                    {
                        continue;
                    }

                    Span<ulong> bucket = buckets.AsSpan(digit * s, s);
                    ReadOnlySpan<ulong> basis = bases.AsSpan(i * s, s);
                    if (filled[digit])
                    {
                        arithmetic.Multiply(bucket, basis, bucket);
                    }
                    else
                    {
                        basis.CopyTo(bucket);
                        filled[digit] = true;
                    }
                }

                // prod_d bucket[d]^d, as a running product of running products: walking d downward,
                // bucket[d] is folded into "running" once and then into "total" d times.
                bool runningEmpty = true;
                bool totalEmpty = true;
                for (int digit = bucketCount - 1; digit >= 1; digit--)
                {
                    if (filled[digit])
                    {
                        Span<ulong> bucket = buckets.AsSpan(digit * s, s);
                        if (runningEmpty)
                        {
                            bucket.CopyTo(running);
                            runningEmpty = false;
                        }
                        else
                        {
                            arithmetic.Multiply(running, bucket, running);
                        }
                    }

                    if (runningEmpty)
                    {
                        continue;
                    }

                    if (totalEmpty)
                    {
                        running.CopyTo(total);
                        totalEmpty = false;
                    }
                    else
                    {
                        arithmetic.Multiply(total, running, total);
                    }
                }

                if (totalEmpty)
                {
                    continue;
                }

                if (accumulatorEmpty)
                {
                    total.CopyTo(accumulator);
                    accumulatorEmpty = false;
                }
                else
                {
                    arithmetic.Multiply(accumulator, total, accumulator);
                }
            }

            if (accumulatorEmpty)
            {
                // Every exponent was zero, which happens with probability 2^-(128n). The product is
                // the identity and the test says nothing; let the caller's rescan decide.
                return false;
            }

            // q itself, as a BigInteger: reduced into Z_q it would be zero, and x^0 = 1 accepts anything.
            Span<ulong> raised = s <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[s];
            raised = raised[..s];
            BigInteger q = EGParameters.Q;
            Span<byte> qBuffer = stackalloc byte[MaxStackAllocExponentBytes];
            ReadOnlySpan<byte> qBytes = q.TryWriteBytes(qBuffer, out int qLength, isUnsigned: true, isBigEndian: true)
                ? qBuffer[..qLength]
                : q.ToByteArray(isUnsigned: true, isBigEndian: true);
            arithmetic.PowMontgomeryInto(accumulator, qBytes, raised);

            return arithmetic.IsOne(raised);
        }
        finally
        {
            ArrayPool<ulong>.Shared.Return(bases);
            ArrayPool<ulong>.Shared.Return(buckets);
            ArrayPool<UInt128>.Shared.Return(exponents);
            // The batch exponents are this verifier's coins; there is no reason to leave them behind.
            ArrayPool<byte>.Shared.Return(randomArray, clearArray: true);
        }
    }

    /// <summary>
    /// The window width minimizing Pippenger's multiplication count for <paramref name="n"/> bases:
    /// each of the 128 / c windows costs n bucket insertions plus about 2^(c+1) to combine buckets.
    /// </summary>
    internal static int ChooseWindowBits(int n)
    {
        int best = 1;
        long bestCost = long.MaxValue;
        for (int c = 1; c <= 10; c++)
        {
            long windows = (BatchExponentBits + c - 1) / c;
            long cost = windows * (n + (2L << c));
            if (cost < bestCost)
            {
                bestCost = cost;
                best = c;
            }
        }

        return best;
    }

    /// <summary>
    /// The Jacobi symbol (value / p), over 64-bit limbs. See <see cref="Jacobi(Span{ulong}, Span{ulong})"/>.
    /// </summary>
    internal static int Jacobi(BigInteger value, MontgomeryContext context)
    {
        int s = context.LimbCount;
        Span<ulong> x = s <= MaxStackAllocLimbs ? stackalloc ulong[MaxStackAllocLimbs] : new ulong[s];
        Span<ulong> y = s <= MaxStackAllocLimbs ? stackalloc ulong[MaxStackAllocLimbs] : new ulong[s];
        x = x[..s];
        y = y[..s];

        // The batch test only asks about values already known to be in (0, p), and reducing those
        // anyway would allocate a 4096-bit quotient and remainder per value. Anything else is still
        // reduced exactly as before.
        BigInteger reduced = value.Sign >= 0 && value < context.Modulus ? value : value % context.Modulus;
        MontgomeryContext.WriteLimbs(reduced, x);
        context.ModulusLimbs.CopyTo(y);

        return Jacobi(x, y);
    }

    /// <summary>
    /// (x / y) for odd y. Both spans are overwritten.
    ///
    /// This runs once per value in a batch, so it has to be cheap next to the exponentiation it
    /// replaces. The batched divstep algorithm (<see cref="TryJacobiDivsteps"/>) is tried first; it has
    /// no proven bound on its step count, so if it has not converged within its budget the answer
    /// comes from the slower but always-terminating binary algorithm instead. Either way the result is
    /// exact.
    /// </summary>
    internal static int Jacobi(Span<ulong> x, Span<ulong> y)
    {
        return TryJacobiDivsteps(x, y, out int symbol) ? symbol : JacobiBinary(x, y);
    }

    /// <summary>Divsteps per batch: as many as the bottom 64 bits of f and g can drive exactly.</summary>
    private const int DivstepsPerBatch = 62;

    /// <summary>
    /// (x / y) for odd y by batched "positive divsteps", ported from libsecp256k1's
    /// secp256k1_jacobi64_maybe_var / secp256k1_modinv64_posdivsteps_62_var, which adapt
    /// Bernstein and Yang's divsteps ("Fast constant-time gcd computation and modular inversion",
    /// 2019) to the Jacobi symbol.
    ///
    /// The binary algorithm touches every limb of both operands once per bit removed, so a 4096-bit
    /// symbol costs thousands of full-width passes. Divsteps decide each step from the bottom bits of
    /// f and g alone. That lets 62 steps run on single 64-bit words, recording their combined effect
    /// as a 2x2 matrix, which is then applied to the full numbers once:
    /// [f, g] = [u v; q r] [f, g] / 2^62. A 4096-bit symbol takes about 150 such updates, over
    /// operands that shrink as it goes.
    ///
    /// The "positive" variant only ever adds a multiple of f to g (where plain divsteps would
    /// subtract), so f and g stay non-negative, and every step has a Jacobi-symbol rule that needs
    /// only bottom bits: (g / f) = (g + w*f / f) for the addition, the second supplementary law for
    /// each halving of g, and quadratic reciprocity for each swap. The running sign is kept in the
    /// low bit of jac. When f reaches 1 the symbol is (-1)^jac.
    ///
    /// Unlike plain divsteps this variant has no proven bound on the number of steps, which is why
    /// libsecp256k1 calls its version "maybe". Returns false, leaving the inputs untouched, if f has
    /// not reached 1 within a budget far above the step counts seen in practice; it will also never
    /// reach 1 when gcd(x, y) > 1, which cannot happen for y = p and 0 &lt; x &lt; p.
    /// </summary>
    internal static bool TryJacobiDivsteps(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, out int symbol)
    {
        int lengthX = SignificantLimbs(x, x.Length);
        int lengthY = SignificantLimbs(y, y.Length);
        if (lengthY == 1 && y[0] == 1)
        {
            symbol = 1;
            return true;
        }

        if (lengthX == 0)
        {
            // (0 / y) = 0 for y > 1. The divsteps would only ever shift a zero g.
            symbol = 0;
            return true;
        }

        int length = Math.Max(lengthX, lengthY);

        // Bernstein and Yang bound plain divsteps at about 2.9 steps per bit; posdivsteps behave
        // similarly in practice. Four steps per bit leaves a wide margin before giving up.
        int maxBatches = (4 * 64 * length) / DivstepsPerBatch + 8;

        Span<ulong> f = length <= MaxStackAllocLimbs ? stackalloc ulong[MaxStackAllocLimbs] : new ulong[length];
        Span<ulong> g = length <= MaxStackAllocLimbs ? stackalloc ulong[MaxStackAllocLimbs] : new ulong[length];
        Span<ulong> wideF = length + 1 <= MaxStackAllocLimbs ? stackalloc ulong[MaxStackAllocLimbs] : new ulong[length + 1];
        Span<ulong> wideG = length + 1 <= MaxStackAllocLimbs ? stackalloc ulong[MaxStackAllocLimbs] : new ulong[length + 1];
        f = f[..length];
        g = g[..length];
        f.Clear();
        g.Clear();
        y[..lengthY].CopyTo(f);
        x[..lengthX].CopyTo(g);

        // eta = -delta, with delta starting at 1.
        long eta = -1;
        int jac = 0;

        for (int batch = 0; batch < maxBatches; batch++)
        {
            eta = PosDivsteps62(eta, f[0], g[0], out Transition transition, ref jac);
            ApplyTransition(f, g, length, transition, wideF, wideG);

            if (f[0] == 1 && SignificantLimbs(f, length) == 1)
            {
                symbol = 1 - 2 * (jac & 1);
                return true;
            }

            // Both operands only shrink; stop carrying a top limb once neither uses it.
            while (length > 1 && f[length - 1] == 0 && g[length - 1] == 0)
            {
                length--;
            }
        }

        symbol = 0;
        return false;
    }

    /// <summary>The combined effect of one batch of divsteps: [f, g] = [U V; Q R] [f, g] / 2^62.</summary>
    private readonly record struct Transition(ulong U, ulong V, ulong Q, ulong R);

    /// <summary>
    /// 62 positive divsteps on the bottom 64 bits of f and g, returning the new eta and the
    /// transition matrix, and folding the steps' Jacobi sign changes into the low bit of
    /// <paramref name="jac"/>. A line-for-line port of libsecp256k1's
    /// secp256k1_modinv64_posdivsteps_62_var; see its comments for the derivation of the formulas
    /// that cancel several low bits of g at once.
    ///
    /// The matrix entries never exceed 2^62 and are all non-negative, because the positive variant
    /// only adds, shifts and swaps.
    /// </summary>
    private static long PosDivsteps62(long eta, ulong f0, ulong g0, out Transition transition, ref int jac)
    {
        ulong u = 1, v = 0, q = 0, r = 1;
        ulong f = f0, g = g0;
        int i = DivstepsPerBatch;

        unchecked
        {
            while (true)
            {
                // A sentinel bit at position i caps the count at the steps remaining.
                int zeros = BitOperations.TrailingZeroCount(g | (ulong.MaxValue << i));

                // That many divsteps at once: each just halves g.
                g >>= zeros;
                u <<= zeros;
                v <<= zeros;
                eta -= zeros;
                i -= zeros;

                // Second supplementary law: halving g an odd number of times flips the sign when
                // f = 3 or 5 mod 8, which is exactly when bits 1 and 2 of f differ.
                jac ^= zeros & (int)((f >> 1) ^ (f >> 2));

                if (i == 0)
                {
                    break;
                }

                // f and g are both odd here.
                ulong w;
                if (eta < 0)
                {
                    eta = -eta;
                    (f, g) = (g, f);
                    (u, q) = (q, u);
                    (v, r) = (r, v);

                    // Reciprocity: swapping flips the sign when both are 3 mod 4.
                    jac ^= (int)((f & g) >> 1);

                    // Cancel up to 6 low bits of g, but no more than the steps remaining, and no
                    // more than eta + 1, after which eta's sign would flip again.
                    int limit = (int)Math.Min(eta + 1, i);
                    ulong mask = (ulong.MaxValue >> (64 - limit)) & 63UL;
                    w = (f * g * (f * f - 2)) & mask;
                }
                else
                {
                    // A simpler formula cancelling up to 4 bits, as eta tends to be small here.
                    int limit = (int)Math.Min(eta + 1, i);
                    ulong mask = (ulong.MaxValue >> (64 - limit)) & 15UL;
                    w = f + (((f + 1) & 4) << 1);
                    w = ((0UL - w) * g) & mask;
                }

                g += f * w;
                q += u * w;
                r += v * w;
            }
        }

        transition = new Transition(u, v, q, r);
        return eta;
    }

    /// <summary>
    /// [f, g] = [U V; Q R] [f, g] / 2^62 over the full operands. The divsteps chose the matrix so
    /// that both numerators are divisible by 2^62 exactly, and the positive variant guarantees
    /// neither result exceeds max(f, g), so both fit back in <paramref name="length"/> limbs.
    /// </summary>
    private static void ApplyTransition(Span<ulong> f, Span<ulong> g, int length, Transition t, Span<ulong> wideF, Span<ulong> wideG)
    {
        // Each product is below 2^62 * 2^64, so two of them plus a carry fit in a UInt128.
        UInt128 carryF = 0;
        UInt128 carryG = 0;
        for (int j = 0; j < length; j++)
        {
            ulong fj = f[j];
            ulong gj = g[j];

            UInt128 sumF = (UInt128)t.U * fj + (UInt128)t.V * gj + carryF;
            UInt128 sumG = (UInt128)t.Q * fj + (UInt128)t.R * gj + carryG;

            wideF[j] = (ulong)sumF;
            wideG[j] = (ulong)sumG;
            carryF = sumF >> 64;
            carryG = sumG >> 64;
        }

        wideF[length] = (ulong)carryF;
        wideG[length] = (ulong)carryG;

        const int shift = DivstepsPerBatch;
        for (int j = 0; j < length; j++)
        {
            f[j] = (wideF[j] >> shift) | (wideF[j + 1] << (64 - shift));
            g[j] = (wideG[j] >> shift) | (wideG[j + 1] << (64 - shift));
        }
    }

    /// <summary>
    /// (x / y) for odd y by the binary algorithm. Both spans are overwritten.
    ///
    /// Each iteration strips factors of two (flipping the sign per the second supplementary law),
    /// swaps the operands when the first is smaller (flipping per quadratic reciprocity), and
    /// subtracts. It always terminates, but touches the full operands once per bit removed, which is
    /// why it is only the fallback for <see cref="TryJacobiDivsteps"/>.
    /// </summary>
    internal static int JacobiBinary(Span<ulong> x, Span<ulong> y)
    {
        int lengthX = SignificantLimbs(x, x.Length);
        int lengthY = SignificantLimbs(y, y.Length);
        int result = 1;

        while (true)
        {
            if (lengthX == 0)
            {
                // gcd is y; the symbol is defined (non-zero) only when that is 1.
                return lengthY == 1 && y[0] == 1 ? result : 0;
            }

            int trailingZeros = TrailingZeroCount(x, lengthX);
            if (trailingZeros > 0)
            {
                lengthX = ShiftRight(x, lengthX, trailingZeros);

                // (2 / y) = -1 exactly when y = 3 or 5 mod 8.
                ulong yMod8 = y[0] & 7;
                if ((trailingZeros & 1) == 1 && (yMod8 == 3 || yMod8 == 5))
                {
                    result = -result;
                }
            }

            if (Compare(x, lengthX, y, lengthY) < 0)
            {
                Span<ulong> swap = x;
                x = y;
                y = swap;
                (lengthX, lengthY) = (lengthY, lengthX);

                // Reciprocity for odd x and y: the sign flips when both are 3 mod 4.
                if ((x[0] & 3) == 3 && (y[0] & 3) == 3)
                {
                    result = -result;
                }
            }

            lengthX = Subtract(x, lengthX, y, lengthY);
        }
    }

    private static int SignificantLimbs(ReadOnlySpan<ulong> value, int length)
    {
        while (length > 0 && value[length - 1] == 0)
        {
            length--;
        }

        return length;
    }

    private static int TrailingZeroCount(ReadOnlySpan<ulong> value, int length)
    {
        for (int i = 0; i < length; i++)
        {
            if (value[i] != 0)
            {
                return i * 64 + BitOperations.TrailingZeroCount(value[i]);
            }
        }

        return 0;
    }

    /// <summary>value >>= bits, returning the new significant length.</summary>
    private static int ShiftRight(Span<ulong> value, int length, int bits)
    {
        int limbShift = bits / 64;
        int bitShift = bits % 64;
        int newLength = length - limbShift;

        if (bitShift == 0)
        {
            for (int i = 0; i < newLength; i++)
            {
                value[i] = value[i + limbShift];
            }
        }
        else
        {
            for (int i = 0; i < newLength - 1; i++)
            {
                value[i] = (value[i + limbShift] >> bitShift) | (value[i + limbShift + 1] << (64 - bitShift));
            }

            value[newLength - 1] = value[length - 1] >> bitShift;
        }

        value[newLength..length].Clear();
        return SignificantLimbs(value, newLength);
    }

    private static int Compare(ReadOnlySpan<ulong> a, int lengthA, ReadOnlySpan<ulong> b, int lengthB)
    {
        if (lengthA != lengthB)
        {
            return lengthA < lengthB ? -1 : 1;
        }

        for (int i = lengthA - 1; i >= 0; i--)
        {
            if (a[i] != b[i])
            {
                return a[i] < b[i] ? -1 : 1;
            }
        }

        return 0;
    }

    /// <summary>a -= b for a >= b, returning the new significant length of a.</summary>
    private static int Subtract(Span<ulong> a, int lengthA, ReadOnlySpan<ulong> b, int lengthB)
    {
        ulong borrow = 0;
        for (int i = 0; i < lengthA; i++)
        {
            ulong ai = a[i];
            ulong bi = i < lengthB ? b[i] : 0;
            ulong difference = unchecked(ai - bi - borrow);
            borrow = (ai < bi || (ai == bi && borrow != 0)) ? 1UL : 0UL;
            a[i] = difference;
        }

        return SignificantLimbs(a, lengthA);
    }
}
