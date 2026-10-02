using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace ElectionGuard.Core.Crypto;

/// <summary>
/// A running product of elements of Z_p (§3.1.1), held in Montgomery form between multiplications.
/// This is what the tally's homomorphic aggregation is: every ballot multiplies each choice's
/// (A, B) by its (alpha, beta), hundreds of thousands of products and nothing else.
///
/// An <see cref="IntegerModP"/> product costs a 4096 x 4096-bit BigInteger multiply and a division
/// by p, about 57 us. One multiply on <see cref="Avx512Montgomery"/> costs about 2.5 us, and on the
/// scalar <see cref="MontgomeryContext"/> about 8 us. The usual price of Montgomery form is
/// converting every input into it, which is itself a Montgomery multiply by R^2 and would halve the
/// gain. This class skips that conversion: each factor is loaded as a plain residue and multiplied
/// straight into the Montgomery-form accumulator, which multiplies the accumulated value by the
/// factor and by R^-1. The accumulator therefore holds the Montgomery form of
/// <c>Value * R^-drift</c>, where drift counts the factors loaded that way, and reading
/// <see cref="Value"/> multiplies the R^drift back in once, at a cost of a short exponentiation
/// rather than one conversion per factor.
///
/// <see cref="Multiply(ModPProduct)"/> combines two products: multiplying two Montgomery-form values
/// leaves Montgomery form, so their drifts simply add. That is what lets a tally be accumulated in
/// independent pieces on several threads and then merged.
///
/// Runs on <see cref="Avx512Montgomery"/> when the hardware has AVX-512F and p fits, and on the
/// scalar <see cref="MontgomeryContext"/> otherwise; R differs between the two, but each instance
/// uses one representation throughout, and <see cref="Value"/> is identical either way.
///
/// Reading <see cref="Value"/> is safe from several threads at once, as reading an
/// <see cref="IntegerModP"/> property is, so that guardians may decrypt one tally concurrently. Every
/// other member mutates the product and must not run concurrently with anything else.
/// </summary>
internal sealed class ModPProduct
{
    /// <summary>Buffers longer than this are heap-allocated rather than stack-allocated.</summary>
    private const int MaxStackAllocWidth = Avx512Montgomery.Lanes;

    private readonly Avx512Montgomery? _engine;
    private readonly MontgomeryContext _context;

    /// <summary>The Montgomery form of <c>Value * R^-_drift</c>.</summary>
    private readonly ulong[] _accumulator;

    private long _drift;

    /// <summary>
    /// <see cref="Value"/> as last computed, or null when a multiply has invalidated it. Boxed so that
    /// a concurrent reader sees either no cache or a complete one: a reference is published
    /// atomically, where a Nullable&lt;IntegerModP&gt; could be read half written.
    /// </summary>
    private StrongBox<IntegerModP>? _value;

    internal ModPProduct(IntegerModP initial)
        : this(initial, allowAvx512: true)
    {
    }

    /// <summary>
    /// With <paramref name="allowAvx512"/> false the scalar representation is used even where
    /// AVX-512F is available, so that tests can check it on every machine.
    /// </summary>
    internal ModPProduct(IntegerModP initial, bool allowAvx512)
    {
        _context = MontgomeryContext.Current;
        _engine = allowAvx512 && Avx512Montgomery.TryGetCurrent(out Avx512Montgomery engine) ? engine : null;
        _accumulator = new ulong[Width];
        Reset(initial);
    }

    /// <summary>Whether the AVX-512 representation is in use, for tests.</summary>
    internal bool UsesAvx512 => _engine is not null;

    private int Width => _engine is not null ? Avx512Montgomery.Lanes : _context.LimbCount;

    private ReadOnlySpan<ulong> One => _engine is not null ? _engine.One : _context.One;

    /// <summary>The product of the initial value and every factor multiplied in since, mod p.</summary>
    internal IntegerModP Value
    {
        get
        {
            StrongBox<IntegerModP>? cached = Volatile.Read(ref _value);
            if (cached is null)
            {
                cached = new StrongBox<IntegerModP>(ComputeValue());
                Volatile.Write(ref _value, cached);
            }

            return cached.Value;
        }
    }

    /// <summary>Discards the accumulated product and starts again from <paramref name="value"/>.</summary>
    internal void Reset(IntegerModP value)
    {
        // Every aggregate starts at 1, and every worker of a parallel tally starts its own, so 1
        // skips the conversion multiply: its Montgomery form is One.
        if (value == 1)
        {
            One.CopyTo(_accumulator);
        }
        else
        {
            ToMontgomery(value.ToBigInteger(), _accumulator);
        }

        _drift = 0;
        _value = new StrongBox<IntegerModP>(value);
    }

    /// <summary>Multiplies <paramref name="factor"/> into the product.</summary>
    internal void Multiply(IntegerModP factor)
    {
        int width = Width;
        Span<ulong> plain = width <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[width];
        plain = plain[..width];

        // Loaded without conversion; the R^-1 this multiply introduces is what _drift counts.
        LoadPlain(factor.ToBigInteger(), plain);
        MultiplyWords(_accumulator, plain, _accumulator);
        _drift++;
        _value = null;
    }

    /// <summary>
    /// Multiplies <paramref name="factor"/>^<paramref name="exponent"/> into the product, for a small
    /// public exponent such as a ballot weight. The exponentiation costs about two multiplies per bit
    /// of <paramref name="exponent"/>, and its operation count varies with that bit length, so it
    /// must not be given a secret.
    /// </summary>
    internal void MultiplyPower(IntegerModP factor, int exponent)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(exponent);

        int width = Width;
        Span<ulong> basis = width <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[width];
        Span<ulong> power = width <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[width];
        basis = basis[..width];
        power = power[..width];

        Span<byte> exponentBytes = stackalloc byte[sizeof(long)];
        ToMontgomery(factor.ToBigInteger(), basis);
        PowMontgomery(basis, MinimalBigEndian(exponent, exponentBytes), power);

        // Both operands are in Montgomery form, so the product is too: no drift.
        MultiplyWords(_accumulator, power, _accumulator);
        _value = null;
    }

    /// <summary>
    /// Multiplies the product accumulated by <paramref name="other"/> into this one. Both must have
    /// been created under the same parameters and in the same representation.
    /// </summary>
    internal void Multiply(ModPProduct other)
    {
        // Compared by representation, not by instance: the engines are cached per modulus and rebuilt
        // whenever p changes, so switching parameters away and back leaves products made before and
        // after holding different instances of the same representation.
        if ((other._engine is null) != (_engine is null) || other._context.Modulus != _context.Modulus)
        {
            throw new ArgumentException("Products in different Montgomery representations cannot be combined.", nameof(other));
        }

        // (V1 R^(1 - d1)) * (V2 R^(1 - d2)) * R^-1 = V1 V2 R^(1 - (d1 + d2)).
        MultiplyWords(_accumulator, other._accumulator, _accumulator);
        _drift += other._drift;
        _value = null;
    }

    private IntegerModP ComputeValue()
    {
        if (_drift == 0)
        {
            return new IntegerModP(FromMontgomery(_accumulator));
        }

        int width = Width;
        Span<ulong> value = width <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[width];
        value = value[..width];

        // Multiplying the Montgomery form of R^drift into the Montgomery form of Value * R^-drift
        // leaves the Montgomery form of Value.
        MultiplyWords(Correction(_drift), _accumulator, value);

        return new IntegerModP(FromMontgomery(value));
    }

    /// <summary>
    /// The Montgomery form of R^<paramref name="drift"/>, from a one-entry cache shared by every
    /// instance. Raising it costs about two multiplies per bit of the drift, some 80 us for a
    /// thousand ballots, and is otherwise paid once per value read. Every choice of a tally has
    /// usually seen the same ballots, so they all share one drift, and the cache turns a cost per
    /// choice into a cost per tally.
    /// </summary>
    private ReadOnlySpan<ulong> Correction(long drift)
    {
        CorrectionEntry? cached = Volatile.Read(ref _lastCorrection);
        if (cached is not null && cached.Drift == drift && cached.Engine == _engine && cached.Context == _context)
        {
            return cached.Words;
        }

        int width = Width;
        Span<ulong> radix = width <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[width];
        radix = radix[..width];
        var words = new ulong[width];

        // Raised from the Montgomery form of R.
        Span<byte> exponentBytes = stackalloc byte[sizeof(long)];
        ToMontgomery(Radix(), radix);
        PowMontgomery(radix, MinimalBigEndian(drift, exponentBytes), words);

        // Published whole, after it is filled in, so a concurrent reader never sees it half built.
        Volatile.Write(ref _lastCorrection, new CorrectionEntry(_engine, _context, drift, words));
        return words;
    }

    private static CorrectionEntry? _lastCorrection;

    private sealed record CorrectionEntry(Avx512Montgomery? Engine, MontgomeryContext Context, long Drift, ulong[] Words);

    /// <summary>R mod p for the representation in use. Its Montgomery form, One, holds it as plain words.</summary>
    private BigInteger Radix()
    {
        return _engine is not null
            ? Avx512Montgomery.FromDigits(_engine.One)
            : MontgomeryContext.FromLimbs(_context.One);
    }

    /// <summary>
    /// The big-endian bytes of a non-negative value with leading zero bytes dropped, so that a small
    /// exponent gets the narrow window and walks only the bits it has.
    /// </summary>
    private static ReadOnlySpan<byte> MinimalBigEndian(long value, Span<byte> buffer)
    {
        BinaryPrimitives.WriteInt64BigEndian(buffer, value);
        int leadingZeroBytes = BitOperations.LeadingZeroCount((ulong)value) / 8;
        return buffer[Math.Min(leadingZeroBytes, buffer.Length - 1)..];
    }

    private void LoadPlain(BigInteger value, Span<ulong> result)
    {
        if (_engine is not null)
        {
            Avx512Montgomery.WriteDigits(value, result);
        }
        else
        {
            MontgomeryContext.WriteLimbs(value, result);
        }
    }

    private void ToMontgomery(BigInteger value, Span<ulong> result)
    {
        if (_engine is not null)
        {
            _engine.ToMontgomery(value, result);
        }
        else
        {
            _context.ToMontgomery(value, result);
        }
    }

    private BigInteger FromMontgomery(ReadOnlySpan<ulong> value)
    {
        return _engine is not null ? _engine.FromMontgomery(value) : _context.FromMontgomery(value);
    }

    private void MultiplyWords(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> result)
    {
        if (_engine is not null)
        {
            _engine.Multiply(a, b, result);
        }
        else
        {
            _context.Multiply(a, b, result);
        }
    }

    private void PowMontgomery(ReadOnlySpan<ulong> basis, ReadOnlySpan<byte> exponentBigEndian, Span<ulong> result)
    {
        if (_engine is not null)
        {
            _engine.PowMontgomeryInto(basis, exponentBigEndian, result);
        }
        else
        {
            MontgomeryModP.PowMontgomeryInto(basis, exponentBigEndian, _context, result);
        }
    }
}
