using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Crypto;

public class PowRadixTests
{
    public PowRadixTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static readonly BigInteger Q = EGParameters.CryptographicParameters.Q;
    private static readonly BigInteger G = EGParameters.CryptographicParameters.G;

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(7)]
    [InlineData(8)]
    public void Pow_MatchesIntegerModP_AcrossWindowWidths(int windowBits)
    {
        // Widths that do not divide 64 are the interesting ones: their windows straddle the
        // boundaries between the exponent's 64-bit words.
        PowRadix radix = PowRadix.Build(G, windowBits);
        Random random = new(windowBits * 1000);

        for (int i = 0; i < 4; i++)
        {
            IntegerModQ exponent = new(MontgomeryModPTests.RandomBelowQ(random));

            Assert.Equal(IntegerModP.PowModP(G, exponent), radix.Pow(exponent));
        }
    }

    [Fact]
    public void Pow_ExponentZero_IsOne()
    {
        PowRadix radix = PowRadix.Build(G);

        Assert.Equal(new IntegerModP(BigInteger.One), radix.Pow(new IntegerModQ(BigInteger.Zero)));
    }

    [Fact]
    public void Pow_ExponentOne_IsTheBase()
    {
        PowRadix radix = PowRadix.Build(G);

        Assert.Equal(new IntegerModP(G), radix.Pow(new IntegerModQ(BigInteger.One)));
    }

    [Fact]
    public void Pow_LargestExponent_MatchesIntegerModP()
    {
        // q-1 sets the most significant window, which is the one a mis-sized table would drop.
        PowRadix radix = PowRadix.Build(G);
        IntegerModQ exponent = new(Q - 1);

        Assert.Equal(IntegerModP.PowModP(G, exponent), radix.Pow(exponent));
    }

    [Fact]
    public void Pow_AgreesWithTheTableFreePath()
    {
        PowRadix radix = PowRadix.Build(G, 4);
        IntegerModQ exponent = new(MontgomeryModPTests.RandomBelowQ(new Random(55)));

        Assert.Equal(MontgomeryModP.PowModP(G, exponent), radix.Pow(exponent));
    }

    [Fact]
    public void Build_ShapeIsDerivedFromTheParameterSizes()
    {
        // §3.1.1: exponents live in Z_q, so the table needs ceil(|q| / windowBits) rows, and each
        // entry is one element of Z_p.
        PowRadix radix = PowRadix.Build(G, 8);

        Assert.Equal(256, radix.ExponentBits);
        Assert.Equal(32, radix.Rows);
        Assert.Equal(256, radix.Columns);
        Assert.Equal(8, radix.WindowBits);

        // 32 rows x 256 entries x 64 limbs x 8 bytes = 4 MiB for scalar limbs, or
        // 32 x 256 x 80 digits x 8 bytes = 5 MiB for AVX-512 digits.
        long expected = radix.UsesAvx512 ? 5L * 1024 * 1024 : 4L * 1024 * 1024;
        Assert.Equal(expected, radix.TableSizeInBytes);
    }

    [Fact]
    public void Build_ScalarTable_IsFourMebibytesAtEightBits()
    {
        PowRadix radix = PowRadix.Build(G, 8, allowAvx512: false);

        Assert.False(radix.UsesAvx512);
        Assert.Equal(4L * 1024 * 1024, radix.TableSizeInBytes);
    }

    [Avx512Fact]
    public void Build_Avx512Table_HoldsTheEnginesOwnDigits()
    {
        // 80 digits of 52 bits, one per ulong, exactly as the engine's multiply reads them: 640
        // bytes an entry.
        PowRadix radix = PowRadix.Build(G, 8);

        Assert.True(radix.UsesAvx512);
        Assert.Equal(32L * 256 * 640, radix.TableSizeInBytes);
    }

    [Fact]
    public void Build_RowsRoundUpWhenTheWindowDoesNotDivideTheExponent()
    {
        PowRadix radix = PowRadix.Build(G, 12);

        Assert.Equal(22, radix.Rows);
        Assert.True(radix.Rows * radix.WindowBits >= radix.ExponentBits);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(17)]
    [InlineData(64)]
    public void Build_RejectsWindowWidthsOutsideTheSupportedRange(int windowBits)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => PowRadix.Build(G, windowBits));
    }

    [Fact]
    public void EstimateTableSizeInBytes_MatchesTheTableActuallyBuilt()
    {
        long estimate = PowRadix.EstimateTableSizeInBytes(4);

        Assert.Equal(estimate, PowRadix.Build(G, 4).TableSizeInBytes);
    }

    [Fact]
    public void EstimateTableSizeInBytes_GrowsAsDocumented()
    {
        // The cost of a wider window at the v2.1.0 parameter sizes, which is why the default stops
        // at 8 and the maximum at 16.
        Assert.Equal(4L * 1024 * 1024, PowRadix.EstimateTableSizeInBytes(8, allowAvx512: false));
        Assert.Equal(44L * 1024 * 1024, PowRadix.EstimateTableSizeInBytes(12, allowAvx512: false));
        Assert.Equal(512L * 1024 * 1024, PowRadix.EstimateTableSizeInBytes(16, allowAvx512: false));
    }

    [Avx512Fact]
    public void EstimateTableSizeInBytes_Avx512_GrowsAsDocumented()
    {
        // 640-byte entries: 5 MiB at 8 bits, 55 MiB at the default 12, 640 MiB at 16.
        Assert.Equal(5L * 1024 * 1024, PowRadix.EstimateTableSizeInBytes(8));
        Assert.Equal(56320L * 1024, PowRadix.EstimateTableSizeInBytes(12));
        Assert.Equal(640L * 1024 * 1024, PowRadix.EstimateTableSizeInBytes(16));
    }

    [Fact]
    public void EstimateTableSizeInBytes_MatchesTheScalarTableActuallyBuilt()
    {
        long estimate = PowRadix.EstimateTableSizeInBytes(4, allowAvx512: false);

        Assert.Equal(estimate, PowRadix.Build(G, 4, allowAvx512: false).TableSizeInBytes);
    }

    public static TheoryData<int> EngineWindowWidths => new() { 1, 4, 8, 12 };

    [Theory]
    [MemberData(nameof(EngineWindowWidths))]
    public void ScalarTable_MatchesModPow_ForRandomAndEdgeExponents(int windowBits)
    {
        AssertMatchesModPow(PowRadix.Build(G, windowBits, allowAvx512: false), windowBits, expectAvx512: false);
    }

    [Avx512Fact]
    public void Avx512Table_MatchesModPow_ForRandomAndEdgeExponents()
    {
        // [Avx512Fact] has no theory counterpart, so the widths are looped over here.
        foreach (int windowBits in new[] { 1, 4, 8, 12 })
        {
            AssertMatchesModPow(PowRadix.Build(G, windowBits), windowBits, expectAvx512: true);
        }
    }

    [Avx512Fact]
    public void Avx512Table_ArbitraryBase_MatchesTheScalarTable()
    {
        Random random = new(4242);
        BigInteger basis = MontgomeryModPTests.RandomBelowP(random);
        PowRadix digits = PowRadix.Build(basis, 5);
        PowRadix limbs = PowRadix.Build(basis, 5, allowAvx512: false);

        Assert.True(digits.UsesAvx512);
        Assert.False(limbs.UsesAvx512);
        for (int i = 0; i < 4; i++)
        {
            IntegerModQ exponent = new(MontgomeryModPTests.RandomBelowQ(random));
            Assert.Equal(limbs.Pow(exponent), digits.Pow(exponent));
        }
    }

    [Avx512Fact]
    public void Avx512Table_IsUsedFromManyThreadsAtOnce()
    {
        // Every buffer is on the caller's stack; a shared scratch buffer would corrupt results here.
        PowRadix radix = PowRadix.Build(G, 8);
        IntegerModQ[] exponents = new IntegerModQ[64];
        Random random = new(99);
        for (int i = 0; i < exponents.Length; i++)
        {
            exponents[i] = new IntegerModQ(MontgomeryModPTests.RandomBelowQ(random));
        }

        IntegerModP[] results = new IntegerModP[exponents.Length];
        Parallel.For(0, exponents.Length, new ParallelOptions { MaxDegreeOfParallelism = 16 }, i => results[i] = radix.Pow(exponents[i]));

        for (int i = 0; i < exponents.Length; i++)
        {
            Assert.Equal(BigInteger.ModPow(G, exponents[i].ToBigInteger(), EGParameters.P), results[i].ToBigInteger());
        }
    }

    private static void AssertMatchesModPow(PowRadix radix, int windowBits, bool expectAvx512)
    {
        Assert.Equal(expectAvx512, radix.UsesAvx512);

        Random random = new(windowBits * 7919);
        List<BigInteger> exponents = [BigInteger.Zero, BigInteger.One, Q - 1];
        for (int i = 0; i < 3; i++)
        {
            exponents.Add(MontgomeryModPTests.RandomBelowQ(random));
        }

        foreach (BigInteger exponent in exponents)
        {
            BigInteger expected = BigInteger.ModPow(G, exponent, EGParameters.P);
            Assert.Equal(expected, radix.Pow(new IntegerModQ(exponent)).ToBigInteger());
        }
    }

    [Fact]
    public void Build_ArbitraryBase_StillMatchesIntegerModP()
    {
        Random random = new(808);
        BigInteger basis = MontgomeryModPTests.RandomBelowP(random);
        IntegerModQ exponent = new(MontgomeryModPTests.RandomBelowQ(random));

        Assert.Equal(IntegerModP.PowModP(basis, exponent), PowRadix.Build(basis, 4).Pow(exponent));
    }
}
