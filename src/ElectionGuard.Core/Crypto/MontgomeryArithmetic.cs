using System.Numerics;

namespace ElectionGuard.Core.Crypto;

/// <summary>
/// The Montgomery-form operations shared by the variable-time algorithms that run on either
/// representation - <see cref="SubgroupMembership"/>'s batch test and
/// <see cref="MontgomeryModP.PowModPVariableTime(BigInteger, ReadOnlySpan{IntegerModQ}, Span{IntegerModP})"/>.
/// Values are spans of <see cref="Width"/> words, in whatever form the implementation uses.
///
/// Callers are generic over this with a struct constraint, so that the JIT compiles one copy per
/// representation with the multiplications called directly rather than through an interface.
/// </summary>
internal interface IMontgomeryArithmetic
{
    int Width { get; }

    /// <summary>Converts a value in [0, p) into Montgomery form.</summary>
    void ToMontgomery(BigInteger value, Span<ulong> result);

    /// <summary>Converts a Montgomery-form value back to an ordinary residue in [0, p).</summary>
    BigInteger FromMontgomery(ReadOnlySpan<ulong> value);

    void Multiply(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> result);

    void Square(ReadOnlySpan<ulong> a, Span<ulong> result);

    void PowMontgomeryInto(ReadOnlySpan<ulong> basis, ReadOnlySpan<byte> exponentBigEndian, Span<ulong> result);

    /// <summary>Whether a Montgomery-form value represents 1.</summary>
    bool IsOne(ReadOnlySpan<ulong> value);

    /// <summary>Whether two Montgomery-form values represent the same residue.</summary>
    bool AreCongruent(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b);

    /// <summary>The Montgomery form of 1.</summary>
    ReadOnlySpan<ulong> One { get; }

    /// <summary>
    /// Converts a Montgomery-form value back to an ordinary residue in [0, p) and writes it as the
    /// fixed-width big-endian bytes <see cref="IntegerModP.ToByteArray"/> would produce, without
    /// building a BigInteger.
    /// </summary>
    void WriteBigEndian(ReadOnlySpan<ulong> value, Span<byte> destination);
}

/// <summary>64-bit limbs, fully reduced, so 1 has exactly one representation.</summary>
internal readonly struct ScalarMontgomeryArithmetic(MontgomeryContext context) : IMontgomeryArithmetic
{
    public int Width => context.LimbCount;

    public void ToMontgomery(BigInteger value, Span<ulong> result) => context.ToMontgomery(value, result);

    public BigInteger FromMontgomery(ReadOnlySpan<ulong> value) => context.FromMontgomery(value);

    public void Multiply(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> result) => context.Multiply(a, b, result);

    public void Square(ReadOnlySpan<ulong> a, Span<ulong> result) => context.Square(a, result);

    public void PowMontgomeryInto(ReadOnlySpan<ulong> basis, ReadOnlySpan<byte> exponentBigEndian, Span<ulong> result)
        => MontgomeryModP.PowMontgomeryInto(basis, exponentBigEndian, context, result);

    public bool IsOne(ReadOnlySpan<ulong> value) => value.SequenceEqual(context.One);

    public bool AreCongruent(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b) => a[..Width].SequenceEqual(b[..Width]);

    public ReadOnlySpan<ulong> One => context.One;

    public void WriteBigEndian(ReadOnlySpan<ulong> value, Span<byte> destination) => context.WriteBigEndian(value, destination);
}

/// <summary>
/// 52-bit digits in [0, 2p), so 1 has two representations; <see cref="Avx512Montgomery.IsOne"/>
/// accepts both. There is no dedicated squaring on this representation, so a square costs a full
/// multiply.
/// </summary>
internal readonly struct Avx512MontgomeryArithmetic(Avx512Montgomery engine) : IMontgomeryArithmetic
{
    public int Width => Avx512Montgomery.Lanes;

    public void ToMontgomery(BigInteger value, Span<ulong> result) => engine.ToMontgomery(value, result);

    public BigInteger FromMontgomery(ReadOnlySpan<ulong> value) => engine.FromMontgomery(value);

    public void Multiply(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> result) => engine.Multiply(a, b, result);

    public void Square(ReadOnlySpan<ulong> a, Span<ulong> result) => engine.Multiply(a, a, result);

    public void PowMontgomeryInto(ReadOnlySpan<ulong> basis, ReadOnlySpan<byte> exponentBigEndian, Span<ulong> result)
        => engine.PowMontgomeryInto(basis, exponentBigEndian, result);

    public bool IsOne(ReadOnlySpan<ulong> value) => engine.IsOne(value);

    public bool AreCongruent(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b) => engine.AreCongruent(a, b);

    public ReadOnlySpan<ulong> One => engine.One;

    public void WriteBigEndian(ReadOnlySpan<ulong> value, Span<byte> destination) => engine.WriteBigEndian(value, destination);
}
