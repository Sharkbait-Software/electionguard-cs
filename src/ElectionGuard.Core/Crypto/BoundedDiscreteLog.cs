using ElectionGuard.Core.Extensions;
using System.Numerics;

namespace ElectionGuard.Core.Crypto;

/// <summary>
/// Discrete logarithms to one fixed base over a bounded range: given t, the exponent e in
/// [0, maxExponent] with basis^e = t mod p. Tally decryption (§3.6) ends in exactly this: the
/// combined partial decryptions leave T = K^t, and the vote count t is at most the number of ballots
/// cast.
///
/// Trying every candidate costs one exponentiation per candidate per choice, so the cost of a
/// decryption grew with the product of ballots and choices. This is the baby-step giant-step
/// algorithm instead. With n = maxExponent + 1 candidates and step m, the table holds basis^j for
/// j in [0, m), and each lookup walks t * basis^(-m a) for a = 0, 1, ... until it lands in the
/// table, at a = floor(e / m), giving e = m a + j. Building the table costs m multiplies, once, and
/// shared by every choice; each lookup costs at most ceil(n / m). The total over L lookups,
/// m + L n / m, is least at m = sqrt(L n), so a whole tally costs about 2 sqrt(L n) multiplies
/// rather than L n exponentiations. For the 75 choices and 1,000 ballots of the xsmall scenario
/// that is about 550 multiplies against 75,075 exponentiations; for a million ballots, about 17,000.
///
/// VARIABLE TIME, FOR PUBLIC VALUES ONLY. Each lookup stops as soon as it finds the exponent, so its
/// running time reveals the exponent, which is fine for a decrypted tally because publishing that
/// count is the point of decrypting it. It must not be used to recover anything secret.
///
/// The table is keyed on the canonical residue in [0, p), never on Montgomery words: the AVX-512
/// representation holds values redundantly in [0, 2p), so equal values need not have equal words.
/// Once built the table is only read, so <see cref="TryFind"/> may be called from several threads.
/// </summary>
internal sealed class BoundedDiscreteLog
{
    /// <summary>Buffers longer than this are heap-allocated rather than stack-allocated.</summary>
    private const int MaxStackAllocWidth = Avx512Montgomery.Lanes;

    private readonly Avx512Montgomery? _engine;
    private readonly MontgomeryContext _context;
    private readonly Dictionary<BigInteger, int> _babySteps;
    private readonly int _step;
    private readonly int _maxExponent;

    /// <summary>The Montgomery form of basis^-step, the giant step.</summary>
    private readonly ulong[] _giantStep;

    /// <summary>
    /// Builds the table for <paramref name="basis"/> and exponents in [0, <paramref name="maxExponent"/>],
    /// sized for about <paramref name="expectedLookups"/> calls to <see cref="TryFind"/>.
    /// </summary>
    internal BoundedDiscreteLog(IntegerModP basis, int maxExponent, int expectedLookups)
        : this(basis, maxExponent, expectedLookups, allowAvx512: true)
    {
    }

    /// <summary>
    /// With <paramref name="allowAvx512"/> false the scalar representation is used even where
    /// AVX-512F is available, so that tests can check it on every machine.
    /// </summary>
    internal BoundedDiscreteLog(IntegerModP basis, int maxExponent, int expectedLookups, bool allowAvx512)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maxExponent);
        if (basis == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(basis), "The basis must be invertible mod p.");
        }

        _context = MontgomeryContext.Current;
        _engine = allowAvx512 && Avx512Montgomery.TryGetCurrent(out Avx512Montgomery engine) ? engine : null;
        _maxExponent = maxExponent;

        long candidates = (long)maxExponent + 1;
        double optimal = Math.Ceiling(Math.Sqrt((double)candidates * Math.Max(1, expectedLookups)));
        _step = (int)Math.Clamp(optimal, 1, candidates);

        int width = Width;
        Span<ulong> montgomeryBasis = width <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[width];
        Span<ulong> power = width <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[width];
        montgomeryBasis = montgomeryBasis[..width];
        power = power[..width];

        ToMontgomery(basis.ToBigInteger(), montgomeryBasis);
        One.CopyTo(power);

        // Baby steps: basis^j for j in [0, step). TryAdd keeps the first, smallest j should the
        // basis have an order below step, which the spec's K, of order q, never does.
        _babySteps = new Dictionary<BigInteger, int>(_step);
        for (int j = 0; j < _step; j++)
        {
            _babySteps.TryAdd(FromMontgomery(power), j);
            MultiplyWords(power, montgomeryBasis, power);
        }

        // power now holds basis^step; the giant step is its inverse.
        BigInteger inverse = FromMontgomery(power).ModInverseVariableTime(_context.Modulus);
        _giantStep = new ulong[width];
        ToMontgomery(inverse, _giantStep);
    }

    /// <summary>Whether the AVX-512 representation is in use, for tests.</summary>
    internal bool UsesAvx512 => _engine is not null;

    /// <summary>The baby-step count chosen, for tests.</summary>
    internal int Step => _step;

    private int Width => _engine is not null ? Avx512Montgomery.Lanes : _context.LimbCount;

    private ReadOnlySpan<ulong> One => _engine is not null ? _engine.One : _context.One;

    /// <summary>
    /// Finds the exponent e in [0, maxExponent] with basis^e = <paramref name="target"/> mod p,
    /// returning false when there is none in that range.
    /// </summary>
    internal bool TryFind(IntegerModP target, out int exponent)
    {
        int width = Width;
        Span<ulong> current = width <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[width];
        current = current[..width];

        // Starting from the target itself avoids a conversion: a = 0 is a plain table lookup.
        BigInteger residue = target.ToBigInteger();
        bool converted = false;

        for (long giantSteps = 0; ; giantSteps++)
        {
            if (_babySteps.TryGetValue(residue, out int babyStep))
            {
                long candidate = giantSteps * _step + babyStep;
                exponent = candidate <= _maxExponent ? (int)candidate : -1;

                // Lookups walk upward from 0, so a match beyond the bound means none within it.
                return exponent >= 0;
            }

            if ((giantSteps + 1) * _step > _maxExponent)
            {
                exponent = -1;
                return false;
            }

            if (!converted)
            {
                ToMontgomery(residue, current);
                converted = true;
            }

            MultiplyWords(current, _giantStep, current);
            residue = FromMontgomery(current);
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
}
