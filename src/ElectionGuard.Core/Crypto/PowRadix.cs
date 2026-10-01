using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.Crypto;

/// <summary>
/// A precomputed table of powers of one fixed base, held in Montgomery form, implementing Note 3.5.
///
/// The note observes that every exponentiation needed to encrypt and prove ballot components has a
/// base of either g or K, so those powers can be computed once and reused. This is the standard
/// fixed-base comb: the exponent is cut into <see cref="WindowBits"/>-wide digits, and the table
/// holds basis^(digit * 2^(WindowBits * row)) for every row and every digit value. An
/// exponentiation then costs <see cref="Rows"/> - 1 multiplications instead of the roughly 340 a
/// 256-bit square-and-multiply needs.
///
/// The table shape is derived from the spec rather than chosen: exponents are elements of Z_q
/// (§3.1.1), so the number of rows is ceil(|q| / WindowBits), and each entry is |p| bits wide.
/// For the v2.1.0 parameters, |q| = 256 and |p| = 4096, so the default 8-bit window gives
/// 32 rows of 256 entries at 512 bytes each: 4 MB per base.
///
/// Building a table is expensive enough that it is opt-in. See <see cref="PowRadixRegistry"/>.
/// </summary>
public sealed class PowRadix
{
    /// <summary>
    /// Bits per window.
    ///
    /// Twelve trades memory for speed: at the v2.1.0 parameter sizes it needs 22 rows of 4096
    /// entries, so 44 MB per base against 4 MB at eight bits, and it cuts an exponentiation from 31
    /// multiplications to 21. The reference Kotlin implementation offers the same width as
    /// PowRadixOption.HIGH_MEMORY_USE, defaulting to eight; this defaults to twelve instead, on the
    /// grounds that a process which has opted into precomputation at all has already decided the
    /// memory is worth spending.
    ///
    /// Callers that disagree pass their own width. See <see cref="EstimateTableSizeInBytes"/>.
    /// </summary>
    public const int DefaultWindowBits = 12;

    public const int MinWindowBits = 1;

    /// <summary>
    /// Above 16 bits the table stops being a table and starts being a memory leak: at |p| = 4096
    /// a 16-bit window already needs 512 MB for a single base.
    /// </summary>
    public const int MaxWindowBits = 16;

    /// <summary>Accumulators longer than this are heap-allocated rather than stack-allocated.</summary>
    private const int MaxStackAllocLimbs = 80;

    private PowRadix(BigInteger basis, int windowBits, MontgomeryContext context, int exponentBits)
    {
        Basis = basis;
        WindowBits = windowBits;
        Context = context;
        ExponentBits = exponentBits;
        Columns = 1 << windowBits;
        Rows = (exponentBits + windowBits - 1) / windowBits;

        int limbs = context.LimbCount;
        long tableLength = (long)Rows * Columns * limbs;
        if (tableLength > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(
                nameof(windowBits),
                windowBits,
                $"A {windowBits}-bit window would need a table of {tableLength * sizeof(ulong)} bytes, which is too large to allocate.");
        }

        _table = new ulong[(int)tableLength];

        BuildTable(basis);
    }

    private readonly ulong[] _table;

    /// <summary>The fixed base whose powers this table holds.</summary>
    public BigInteger Basis { get; }

    public int WindowBits { get; }

    /// <summary>Number of windows the exponent is cut into, ceil(|q| / WindowBits).</summary>
    public int Rows { get; }

    /// <summary>Number of distinct digit values per window, 2^WindowBits.</summary>
    public int Columns { get; }

    /// <summary>Bit width of the exponents this table can raise its base to, taken from |q|.</summary>
    public int ExponentBits { get; }

    internal MontgomeryContext Context { get; }

    /// <summary>Bytes occupied by the table itself.</summary>
    public long TableSizeInBytes => (long)_table.Length * sizeof(ulong);

    /// <summary>
    /// Bytes a table would occupy for the active parameters, so callers can check the cost before
    /// paying it.
    /// </summary>
    public static long EstimateTableSizeInBytes(int windowBits)
    {
        ValidateWindowBits(windowBits);

        MontgomeryContext context = MontgomeryContext.Current;
        int exponentBits = (int)EGParameters.Q.GetBitLength();
        long rows = (exponentBits + windowBits - 1) / windowBits;
        return rows * (1L << windowBits) * context.LimbCount * sizeof(ulong);
    }

    public static PowRadix Build(IntegerModP basis, int windowBits = DefaultWindowBits)
    {
        return Build(basis.ToBigInteger(), windowBits);
    }

    public static PowRadix Build(BigInteger basis, int windowBits = DefaultWindowBits)
    {
        ValidateWindowBits(windowBits);

        MontgomeryContext context = MontgomeryContext.Current;
        int exponentBits = (int)EGParameters.Q.GetBitLength();
        return new PowRadix(basis.Mod(context.Modulus), windowBits, context, exponentBits);
    }

    private static void ValidateWindowBits(int windowBits)
    {
        if (windowBits < MinWindowBits || windowBits > MaxWindowBits)
        {
            throw new ArgumentOutOfRangeException(
                nameof(windowBits),
                windowBits,
                $"Window width must be between {MinWindowBits} and {MaxWindowBits} bits.");
        }
    }

    private void BuildTable(BigInteger basis)
    {
        int limbs = Context.LimbCount;

        // The base for row i is basis^(2^(WindowBits * i)). Each is the previous one squared
        // WindowBits times, so they have to be produced in order; that is cheap, Rows * WindowBits
        // squarings in total.
        ulong[] rowBases = new ulong[Rows * limbs];
        Context.ToMontgomery(basis, rowBases.AsSpan(0, limbs));
        for (int row = 1; row < Rows; row++)
        {
            Span<ulong> previous = rowBases.AsSpan((row - 1) * limbs, limbs);
            Span<ulong> current = rowBases.AsSpan(row * limbs, limbs);
            previous.CopyTo(current);
            for (int square = 0; square < WindowBits; square++)
            {
                Context.Multiply(current, current, current);
            }
        }

        // Rows are independent once their bases are known, and filling them is the bulk of the cost,
        // so do it in parallel. Each row writes a disjoint slice.
        Parallel.For(0, Rows, row =>
        {
            ReadOnlySpan<ulong> rowBasis = rowBases.AsSpan(row * limbs, limbs);
            long rowStart = (long)row * Columns * limbs;

            Context.One.CopyTo(_table.AsSpan((int)rowStart, limbs));
            for (int column = 1; column < Columns; column++)
            {
                Span<ulong> previous = _table.AsSpan((int)(rowStart + (long)(column - 1) * limbs), limbs);
                Span<ulong> current = _table.AsSpan((int)(rowStart + (long)column * limbs), limbs);
                Context.Multiply(previous, rowBasis, current);
            }
        });
    }

    /// <summary>
    /// Computes Basis^exponent mod p by multiplying together one table entry per window.
    ///
    /// Every row contributes a multiplication, including rows whose digit is zero. Skipping those
    /// would save well under 1% at an 8-bit window while making the operation count depend on a
    /// secret exponent, so the uniform version is the one worth having. The table index still
    /// depends on the exponent, so this is not constant-time against cache-timing analysis; neither
    /// is the BigInteger.ModPow path it replaces.
    /// </summary>
    public IntegerModP Pow(IntegerModQ exponent)
    {
        int limbs = Context.LimbCount;

        Span<ulong> accumulator = limbs <= MaxStackAllocLimbs ? stackalloc ulong[MaxStackAllocLimbs] : new ulong[limbs];
        accumulator = accumulator[..limbs];

        PowInto(exponent, accumulator);
        return new IntegerModP(Context.FromMontgomery(accumulator));
    }

    /// <summary>Writes the Montgomery-form result of Basis^exponent into <paramref name="result"/>.</summary>
    internal void PowInto(IntegerModQ exponent, Span<ulong> result)
    {
        int limbs = Context.LimbCount;

        // The exponent as little-endian 64-bit words, with one guard word so that a window
        // straddling a word boundary can always read the next one.
        int words = (ExponentBits + 63) / 64;
        Span<ulong> e = stackalloc ulong[words + 1];
        e.Clear();

        byte[] bigEndian = exponent.ToByteArray();
        for (int i = 0; i < bigEndian.Length; i++)
        {
            int positionFromLeastSignificant = bigEndian.Length - 1 - i;
            if (positionFromLeastSignificant >= words * sizeof(ulong))
            {
                continue;
            }

            e[positionFromLeastSignificant >> 3] |= (ulong)bigEndian[i] << ((positionFromLeastSignificant & 7) * 8);
        }

        ulong mask = WindowBits == 64 ? ulong.MaxValue : (1UL << WindowBits) - 1;

        _table.AsSpan(DigitOffset(0, ReadDigit(e, 0, mask), limbs), limbs).CopyTo(result);
        for (int row = 1; row < Rows; row++)
        {
            int digit = ReadDigit(e, row, mask);
            Context.Multiply(result, _table.AsSpan(DigitOffset(row, digit, limbs), limbs), result);
        }
    }

    private int ReadDigit(ReadOnlySpan<ulong> exponentWords, int row, ulong mask)
    {
        int bitOffset = row * WindowBits;
        int word = bitOffset >> 6;
        int shift = bitOffset & 63;

        ulong digit = exponentWords[word] >> shift;
        if (shift + WindowBits > 64)
        {
            // shift is non-zero here, so the complementary shift stays in range.
            digit |= exponentWords[word + 1] << (64 - shift);
        }

        return (int)(digit & mask);
    }

    private int DigitOffset(int row, int digit, int limbs)
    {
        return (int)(((long)row * Columns + digit) * limbs);
    }
}
