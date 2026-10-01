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

        // 32 rows x 256 entries x 64 limbs x 8 bytes = 4 MB.
        Assert.Equal(4L * 1024 * 1024, radix.TableSizeInBytes);
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
        Assert.Equal(4L * 1024 * 1024, PowRadix.EstimateTableSizeInBytes(8));
        Assert.Equal(512L * 1024 * 1024, PowRadix.EstimateTableSizeInBytes(16));
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
