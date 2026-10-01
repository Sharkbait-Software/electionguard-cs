using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;

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
/// For the v2.1.0 parameters, |q| = 256 and |p| = 4096.
///
/// Entries are held in one of two representations, chosen when the table is built:
///
/// - When <see cref="Avx512Montgomery"/> is available for the active p, an entry is that engine's
///   144 digits of 29 bits, packed one per uint: 576 bytes. The engine itself works on one digit per
///   64-bit lane, 1152 bytes; entries are widened to that as they are read, which is a handful of
///   vector instructions against a multiply of a couple of microseconds, so the table is kept at
///   half the size. An 8-bit window is then 32 rows of 256 entries, 4.5 MiB per base, and the
///   default 12-bit window 49.5 MiB.
/// - Otherwise an entry is <see cref="MontgomeryContext"/>'s 64 limbs of 64 bits, 512 bytes:
///   4 MiB per base at 8 bits, 44 MiB at 12.
///
/// <see cref="TableSizeInBytes"/> reports whichever was built, and
/// <see cref="EstimateTableSizeInBytes"/> whichever would be. The results are identical either way.
///
/// Building a table is expensive enough that it is opt-in. See <see cref="PowRadixRegistry"/>.
/// </summary>
public sealed class PowRadix
{
    /// <summary>
    /// Bits per window.
    ///
    /// Twelve trades memory for speed: at the v2.1.0 parameter sizes it needs 22 rows of 4096
    /// entries, so 44 MiB per base against 4 MiB at eight bits (49.5 MiB against 4.5 MiB on
    /// AVX-512), and it cuts an exponentiation from 31 multiplications to 21. The reference Kotlin
    /// implementation offers the same width as PowRadixOption.HIGH_MEMORY_USE, defaulting to eight;
    /// this defaults to twelve instead, on the grounds that a process which has opted into
    /// precomputation at all has already decided the memory is worth spending.
    ///
    /// Callers that disagree pass their own width. See <see cref="EstimateTableSizeInBytes"/>.
    /// </summary>
    public const int DefaultWindowBits = 12;

    public const int MinWindowBits = 1;

    /// <summary>
    /// Above 16 bits the table stops being a table and starts being a memory leak: at |p| = 4096
    /// a 16-bit window already needs 512 MiB for a single base (576 MiB on AVX-512).
    /// </summary>
    public const int MaxWindowBits = 16;

    /// <summary>Accumulators longer than this are heap-allocated rather than stack-allocated.</summary>
    private const int MaxStackAllocLimbs = 80;

    /// <summary>Bytes per entry of an AVX-512 table: one uint per 29-bit digit.</summary>
    private const int DigitEntryBytes = Avx512Montgomery.Lanes * sizeof(uint);

    private PowRadix(BigInteger basis, int windowBits, MontgomeryContext context, Avx512Montgomery? engine, int exponentBits)
    {
        Basis = basis;
        WindowBits = windowBits;
        Context = context;
        Engine = engine;
        ExponentBits = exponentBits;
        Columns = 1 << windowBits;
        Rows = (exponentBits + windowBits - 1) / windowBits;

        int width = engine is not null ? Avx512Montgomery.Lanes : context.LimbCount;
        long tableLength = (long)Rows * Columns * width;
        if (tableLength > Array.MaxLength)
        {
            int elementSize = engine is not null ? sizeof(uint) : sizeof(ulong);
            throw new ArgumentOutOfRangeException(
                nameof(windowBits),
                windowBits,
                $"A {windowBits}-bit window would need a table of {tableLength * elementSize} bytes, which is too large to allocate.");
        }

        if (engine is not null)
        {
            _digitTable = new uint[tableLength];
            BuildDigitTable(basis, engine);
        }
        else
        {
            _limbTable = new ulong[tableLength];
            BuildLimbTable(basis);
        }
    }

    /// <summary>The scalar table: <see cref="MontgomeryContext.LimbCount"/> limbs per entry. Null when <see cref="_digitTable"/> is used.</summary>
    private readonly ulong[]? _limbTable;

    /// <summary>The AVX-512 table: <see cref="Avx512Montgomery.Lanes"/> 29-bit digits per entry, one per uint. Null when <see cref="_limbTable"/> is used.</summary>
    private readonly uint[]? _digitTable;

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

    /// <summary>The engine the table was built for, or null when it holds scalar limbs.</summary>
    internal Avx512Montgomery? Engine { get; }

    /// <summary>Whether the entries are held in <see cref="Avx512Montgomery"/>'s digit representation.</summary>
    internal bool UsesAvx512 => _digitTable is not null;

    /// <summary>Bytes occupied by the table itself.</summary>
    public long TableSizeInBytes => _digitTable is not null
        ? (long)_digitTable.Length * sizeof(uint)
        : (long)_limbTable!.Length * sizeof(ulong);

    /// <summary>
    /// Bytes a table would occupy for the active parameters, in the representation
    /// <see cref="Build(BigInteger, int)"/> would choose on this machine, so callers can check the
    /// cost before paying it.
    /// </summary>
    public static long EstimateTableSizeInBytes(int windowBits)
    {
        return EstimateTableSizeInBytes(windowBits, allowAvx512: true);
    }

    /// <inheritdoc cref="EstimateTableSizeInBytes(int)"/>
    internal static long EstimateTableSizeInBytes(int windowBits, bool allowAvx512)
    {
        ValidateWindowBits(windowBits);

        int exponentBits = (int)EGParameters.Q.GetBitLength();
        long rows = (exponentBits + windowBits - 1) / windowBits;
        long entryBytes = allowAvx512 && Avx512Montgomery.TryGetCurrent(out _)
            ? DigitEntryBytes
            : MontgomeryContext.Current.LimbCount * sizeof(ulong);
        return rows * (1L << windowBits) * entryBytes;
    }

    public static PowRadix Build(IntegerModP basis, int windowBits = DefaultWindowBits)
    {
        return Build(basis.ToBigInteger(), windowBits);
    }

    public static PowRadix Build(BigInteger basis, int windowBits = DefaultWindowBits)
    {
        return Build(basis, windowBits, allowAvx512: true);
    }

    /// <summary>
    /// <see cref="Build(BigInteger, int)"/> with the AVX-512 representation optionally ruled out, so
    /// that tests can check the scalar table on hardware that would otherwise never build one.
    /// </summary>
    internal static PowRadix Build(BigInteger basis, int windowBits, bool allowAvx512)
    {
        ValidateWindowBits(windowBits);

        MontgomeryContext context = MontgomeryContext.Current;
        Avx512Montgomery? engine = allowAvx512 && Avx512Montgomery.TryGetCurrent(out Avx512Montgomery current) ? current : null;
        int exponentBits = (int)EGParameters.Q.GetBitLength();
        return new PowRadix(basis.Mod(context.Modulus), windowBits, context, engine, exponentBits);
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

    private void BuildLimbTable(BigInteger basis)
    {
        ulong[] table = _limbTable!;
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

            Context.One.CopyTo(table.AsSpan((int)rowStart, limbs));
            for (int column = 1; column < Columns; column++)
            {
                Span<ulong> previous = table.AsSpan((int)(rowStart + (long)(column - 1) * limbs), limbs);
                Span<ulong> current = table.AsSpan((int)(rowStart + (long)column * limbs), limbs);
                Context.Multiply(previous, rowBasis, current);
            }
        });
    }

    /// <summary>
    /// The same construction as <see cref="BuildLimbTable"/>, on <see cref="Avx512Montgomery"/>.
    /// Every product the engine returns is fully carried, each digit below 2^29, so narrowing it to
    /// a uint loses nothing. Values stay in the engine's redundant [0, 2p) range, which is what its
    /// multiply accepts.
    /// </summary>
    private void BuildDigitTable(BigInteger basis, Avx512Montgomery engine)
    {
        uint[] table = _digitTable!;
        const int lanes = Avx512Montgomery.Lanes;

        ulong[] rowBases = new ulong[Rows * lanes];
        engine.ToMontgomery(basis, rowBases.AsSpan(0, lanes));
        for (int row = 1; row < Rows; row++)
        {
            Span<ulong> previous = rowBases.AsSpan((row - 1) * lanes, lanes);
            Span<ulong> current = rowBases.AsSpan(row * lanes, lanes);
            previous.CopyTo(current);
            for (int square = 0; square < WindowBits; square++)
            {
                engine.Multiply(current, current, current);
            }
        }

        Parallel.For(0, Rows, row =>
        {
            ReadOnlySpan<ulong> rowBasis = rowBases.AsSpan(row * lanes, lanes);
            long rowStart = (long)row * Columns * lanes;

            // The running power is kept widened, so each column costs one multiply and one narrow.
            Span<ulong> current = stackalloc ulong[lanes];
            engine.One.CopyTo(current);
            Narrow(current, table.AsSpan(checked((int)rowStart), lanes));
            for (int column = 1; column < Columns; column++)
            {
                engine.Multiply(current, rowBasis, current);
                Narrow(current, table.AsSpan(checked((int)(rowStart + (long)column * lanes)), lanes));
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
    ///
    /// Nothing is allocated but the result; every buffer is on the caller's stack, so this is safe to
    /// call from many threads at once.
    /// </summary>
    public IntegerModP Pow(IntegerModQ exponent)
    {
        // The exponent as little-endian 64-bit words, with one guard word so that a window
        // straddling a word boundary can always read the next one.
        int words = (ExponentBits + 63) / 64;
        Span<ulong> e = words < 16 ? stackalloc ulong[16] : new ulong[words + 1];
        e = e[..(words + 1)];
        ReadExponentWords(exponent.ToBigInteger(), e);

        if (Engine is not null)
        {
            Span<ulong> accumulator = stackalloc ulong[Avx512Montgomery.Lanes];
            PowDigits(e, accumulator);
            return new IntegerModP(Engine.FromMontgomery(accumulator));
        }

        int limbs = Context.LimbCount;
        Span<ulong> limbAccumulator = limbs <= MaxStackAllocLimbs ? stackalloc ulong[MaxStackAllocLimbs] : new ulong[limbs];
        limbAccumulator = limbAccumulator[..limbs];

        PowLimbs(e, limbAccumulator);
        return new IntegerModP(Context.FromMontgomery(limbAccumulator));
    }

    private void ReadExponentWords(BigInteger exponent, Span<ulong> words)
    {
        words.Clear();
        Span<byte> bytes = System.Runtime.InteropServices.MemoryMarshal.AsBytes(words);
        if (!exponent.TryWriteBytes(bytes, out _, isUnsigned: true, isBigEndian: false))
        {
            throw new ArgumentOutOfRangeException(nameof(exponent), $"Exponent is wider than the {ExponentBits} bits this table was built for.");
        }

        if (!BitConverter.IsLittleEndian)
        {
            for (int i = 0; i < words.Length; i++)
            {
                words[i] = BinaryPrimitives.ReverseEndianness(words[i]);
            }
        }
    }

    /// <summary>The scalar comb, leaving the Montgomery-form result in <paramref name="result"/>.</summary>
    private void PowLimbs(ReadOnlySpan<ulong> e, Span<ulong> result)
    {
        ulong[] table = _limbTable!;
        int limbs = Context.LimbCount;
        ulong mask = (1UL << WindowBits) - 1;

        table.AsSpan(EntryOffset(0, ReadDigit(e, 0, mask), limbs), limbs).CopyTo(result);
        for (int row = 1; row < Rows; row++)
        {
            int digit = ReadDigit(e, row, mask);
            Context.Multiply(result, table.AsSpan(EntryOffset(row, digit, limbs), limbs), result);
        }
    }

    /// <summary>
    /// The AVX-512 comb, leaving the engine's Montgomery-form result, in [0, 2p), in
    /// <paramref name="result"/>. Each selected entry is widened into a stack buffer and multiplied in.
    /// </summary>
    private void PowDigits(ReadOnlySpan<ulong> e, Span<ulong> result)
    {
        uint[] table = _digitTable!;
        Avx512Montgomery engine = Engine!;
        const int lanes = Avx512Montgomery.Lanes;
        ulong mask = (1UL << WindowBits) - 1;

        Span<ulong> entry = stackalloc ulong[lanes];

        Widen(table.AsSpan(EntryOffset(0, ReadDigit(e, 0, mask), lanes), lanes), result);
        for (int row = 1; row < Rows; row++)
        {
            int digit = ReadDigit(e, row, mask);
            Widen(table.AsSpan(EntryOffset(row, digit, lanes), lanes), entry);
            engine.Multiply(result, entry, result);
        }
    }

    /// <summary>Zero-extends <see cref="Avx512Montgomery.Lanes"/> uint digits to ulong lanes.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Widen(ReadOnlySpan<uint> packed, Span<ulong> lanes)
    {
        const int vectors = Avx512Montgomery.Lanes / 16;
        if (packed.Length < Avx512Montgomery.Lanes || lanes.Length < Avx512Montgomery.Lanes)
        {
            throw new ArgumentException($"Entries have {Avx512Montgomery.Lanes} digits.");
        }

        ref uint source = ref System.Runtime.InteropServices.MemoryMarshal.GetReference(packed);
        ref ulong destination = ref System.Runtime.InteropServices.MemoryMarshal.GetReference(lanes);
        for (int v = 0; v < vectors; v++)
        {
            (Vector512<ulong> lower, Vector512<ulong> upper) = Vector512.Widen(Vector512.LoadUnsafe(ref source, (nuint)(v * 16)));
            lower.StoreUnsafe(ref destination, (nuint)(v * 16));
            upper.StoreUnsafe(ref destination, (nuint)(v * 16 + 8));
        }
    }

    /// <summary>Packs fully carried digits, each below 2^29, one per uint.</summary>
    private static void Narrow(ReadOnlySpan<ulong> lanes, Span<uint> packed)
    {
        for (int k = 0; k < Avx512Montgomery.Lanes; k++)
        {
            packed[k] = (uint)lanes[k];
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

    private int EntryOffset(int row, int digit, int width)
    {
        return checked((int)(((long)row * Columns + digit) * width));
    }
}
