using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Crypto;

/// <summary>
/// <see cref="MontgomeryModP.PowModPVariableTime(BigInteger, ReadOnlySpan{IntegerModQ}, Span{IntegerModP})"/>:
/// one base raised to several public exponents over a shared squaring chain. Every case is checked
/// against BigInteger.ModPow.
///
/// Each case runs twice, once letting the public entry point pick its engine (AVX-512 where the
/// hardware has it) and once with AVX-512 ruled out, so the scalar fallback is covered on every
/// machine. Running with DOTNET_EnableAVX512F=0 makes both runs scalar.
/// </summary>
public class MontgomeryModPVariableTimeTests
{
    public MontgomeryModPVariableTimeTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
        PowRadixRegistry.Clear();
    }

    private static readonly BigInteger P = EGParameters.CryptographicParameters.P;
    private static readonly BigInteger Q = EGParameters.CryptographicParameters.Q;

    public static TheoryData<bool> Engines => new() { true, false };

    public static TheoryData<int, bool> CountsAndEngines()
    {
        TheoryData<int, bool> data = new();
        foreach (int count in new[] { 1, 2, 3 })
        {
            data.Add(count, true);
            data.Add(count, false);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(CountsAndEngines))]
    public void RandomBasesAndExponents_MatchModPow(int exponentCount, bool allowAvx512)
    {
        Random random = new(20261001 + exponentCount);

        for (int trial = 0; trial < 8; trial++)
        {
            BigInteger basis = RandomBelow(random, P);
            BigInteger[] exponents = Enumerable.Range(0, exponentCount).Select(_ => RandomBelow(random, Q)).ToArray();

            AssertMatchesModPow(basis, exponents, allowAvx512);
        }
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void ZeroExponent_IsOne(bool allowAvx512)
    {
        AssertMatchesModPow(RandomBelow(new Random(1), P), [BigInteger.Zero], allowAvx512);
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void AllZeroExponents_AreOne_EvenForBaseZero(bool allowAvx512)
    {
        IntegerModP[] results = Pow(BigInteger.Zero, [BigInteger.Zero, BigInteger.Zero], allowAvx512);

        Assert.All(results, r => Assert.Equal(new IntegerModP(BigInteger.One), r));
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void ExponentQMinusOne_MatchesModPow(bool allowAvx512)
    {
        AssertMatchesModPow(RandomBelow(new Random(2), P), [Q - 1], allowAvx512);
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void MixedZeroAndQMinusOne_MatchModPow(bool allowAvx512)
    {
        AssertMatchesModPow(RandomBelow(new Random(3), P), [BigInteger.Zero, Q - 1, BigInteger.One], allowAvx512);
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void ShortExponentAlongsideFullWidthOne_MatchModPow(bool allowAvx512)
    {
        // The chain is sized by the longest exponent; the short one must read zero digits above
        // its own length rather than garbage.
        AssertMatchesModPow(RandomBelow(new Random(4), P), [new BigInteger(5), Q - 2, new BigInteger(0xFFFF)], allowAvx512);
    }

    [Theory]
    [InlineData(1, true)]
    [InlineData(1, false)]
    [InlineData(2, true)]
    [InlineData(2, false)]
    [InlineData(3, true)]
    [InlineData(3, false)]
    [InlineData(255, true)]
    [InlineData(255, false)]
    public void SmallExponentsOnly_MatchModPow(int exponent, bool allowAvx512)
    {
        // Short exponents pick a narrower window, including widths that do not divide 8, so digits
        // straddle byte boundaries.
        AssertMatchesModPow(RandomBelow(new Random(5), P), [new BigInteger(exponent), new BigInteger(exponent + 1)], allowAvx512);
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void SixtyFourBitExponents_ThreeBitWindowStraddlingBytes_MatchModPow(bool allowAvx512)
    {
        // 64-bit exponents choose w = 3 (pinned in WindowChoice_ByOperationCount), whose digits
        // cross byte boundaries.
        Random random = new(9);
        BigInteger[] exponents = Enumerable.Range(0, 2).Select(_ => RandomBelow(random, BigInteger.One << 64) | (BigInteger.One << 63)).ToArray();
        AssertMatchesModPow(RandomBelow(random, P), exponents, allowAvx512);
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void ExponentWithEveryDigitSet_MatchesModPow(bool allowAvx512)
    {
        // All-ones exponent: every 4-bit digit is the maximum, so every x_i lands in the first bucket.
        BigInteger allOnes = (BigInteger.One << 255) - 1;
        AssertMatchesModPow(RandomBelow(new Random(6), P), [allOnes], allowAvx512);
    }

    [Theory]
    [InlineData("1", true)]
    [InlineData("1", false)]
    [InlineData("P-1", true)]
    [InlineData("P-1", false)]
    [InlineData("0", true)]
    [InlineData("0", false)]
    public void EdgeBases_MatchModPow(string which, bool allowAvx512)
    {
        BigInteger basis = which switch
        {
            "0" => BigInteger.Zero,
            "1" => BigInteger.One,
            "P-1" => P - 1,
            _ => throw new ArgumentOutOfRangeException(nameof(which)),
        };

        AssertMatchesModPow(basis, [Q - 1, new BigInteger(2), new BigInteger(3), BigInteger.Zero], allowAvx512);
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void UnreducedBasis_IsReducedModP(bool allowAvx512)
    {
        BigInteger basis = RandomBelow(new Random(8), P);
        IntegerModQ[] exponents = [new IntegerModQ(Q - 1), new IntegerModQ(new BigInteger(12345))];
        IntegerModP[] results = new IntegerModP[2];

        MontgomeryModP.PowModPVariableTime(basis + 3 * P, exponents, results, allowAvx512);

        Assert.Equal(new IntegerModP(BigInteger.ModPow(basis, Q - 1, P)), results[0]);
        Assert.Equal(new IntegerModP(BigInteger.ModPow(basis, 12345, P)), results[1]);
    }

    [Fact]
    public void EmptyExponents_DoNothing()
    {
        MontgomeryModP.PowModPVariableTime(new BigInteger(7), ReadOnlySpan<IntegerModQ>.Empty, Span<IntegerModP>.Empty);
    }

    [Fact]
    public void MismatchedResultLength_Throws()
    {
        IntegerModQ[] exponents = [new IntegerModQ(BigInteger.One), new IntegerModQ(new BigInteger(2))];
        IntegerModP[] results = new IntegerModP[1];

        Assert.Throws<ArgumentException>(() => MontgomeryModP.PowModPVariableTime(new BigInteger(7), exponents, results));
    }

    [Fact]
    public void TabledBase_UsesTableAndMatchesModPow()
    {
        BigInteger g = EGParameters.CryptographicParameters.G;
        PowRadixRegistry.Precompute(g);
        try
        {
            AssertMatchesModPow(g, [Q - 1, new BigInteger(12345), BigInteger.Zero], allowAvx512: true);
        }
        finally
        {
            PowRadixRegistry.Clear();
        }
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void MatchesConstantTimePath(bool allowAvx512)
    {
        Random random = new(7);
        BigInteger basis = RandomBelow(random, P);
        IntegerModQ[] exponents = [new IntegerModQ(RandomBelow(random, Q)), new IntegerModQ(RandomBelow(random, Q))];
        IntegerModP[] results = new IntegerModP[2];

        MontgomeryModP.PowModPVariableTime(basis, exponents, results, allowAvx512);

        Assert.Equal(MontgomeryModP.PowModP(basis, exponents[0]), results[0]);
        Assert.Equal(MontgomeryModP.PowModP(basis, exponents[1]), results[1]);
    }

    [Theory]
    [InlineData(256, 1, 1.0, 4)]
    [InlineData(256, 2, 1.0, 4)]
    [InlineData(256, 3, 1.0, 4)]
    [InlineData(256, 1, 0.75, 4)]
    [InlineData(256, 2, 0.75, 4)]
    [InlineData(255, 2, 1.0, 4)]
    [InlineData(64, 2, 1.0, 3)]
    [InlineData(1, 2, 1.0, 1)]
    public void WindowChoice_ByOperationCount(long bits, int exponentCount, double squareCost, int expectedWindowBits)
    {
        Assert.Equal(expectedWindowBits, MontgomeryModP.ChooseSharedSquaringWindowBits(bits, exponentCount, squareCost));
    }

    [Fact]
    public void ManyParallelCallers_AgreeWithModPow()
    {
        // No shared scratch state: the verifier runs this from many threads at once.
        BigInteger[] bases = Enumerable.Range(0, 32).Select(i => RandomBelow(new Random(100 + i), P)).ToArray();
        IntegerModQ[] exponents = [new IntegerModQ(RandomBelow(new Random(99), Q)), new IntegerModQ(RandomBelow(new Random(98), Q))];

        IntegerModP[][] results = new IntegerModP[bases.Length][];
        Parallel.For(0, bases.Length, i =>
        {
            results[i] = new IntegerModP[exponents.Length];
            MontgomeryModP.PowModPVariableTime(bases[i], exponents, results[i]);
        });

        for (int i = 0; i < bases.Length; i++)
        {
            for (int k = 0; k < exponents.Length; k++)
            {
                Assert.Equal(new IntegerModP(BigInteger.ModPow(bases[i], exponents[k].ToBigInteger(), P)), results[i][k]);
            }
        }
    }

    private static void AssertMatchesModPow(BigInteger basis, BigInteger[] exponents, bool allowAvx512)
    {
        IntegerModP[] results = Pow(basis, exponents, allowAvx512);

        for (int k = 0; k < exponents.Length; k++)
        {
            Assert.Equal(new IntegerModP(BigInteger.ModPow(basis, exponents[k], P)), results[k]);
        }
    }

    private static IntegerModP[] Pow(BigInteger basis, BigInteger[] exponents, bool allowAvx512)
    {
        IntegerModQ[] modQ = exponents.Select(e => new IntegerModQ(e)).ToArray();
        IntegerModP[] results = new IntegerModP[exponents.Length];
        MontgomeryModP.PowModPVariableTime(basis, modQ, results, allowAvx512);
        return results;
    }

    private static BigInteger RandomBelow(Random random, BigInteger bound)
    {
        byte[] bytes = new byte[bound.GetByteCount(isUnsigned: true) + 8];
        random.NextBytes(bytes);
        return new BigInteger(bytes, isUnsigned: true) % bound;
    }
}
