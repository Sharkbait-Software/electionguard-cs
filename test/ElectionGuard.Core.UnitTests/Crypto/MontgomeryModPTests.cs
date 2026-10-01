using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Crypto;

public class MontgomeryModPTests
{
    public MontgomeryModPTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static readonly BigInteger P = EGParameters.CryptographicParameters.P;
    private static readonly BigInteger Q = EGParameters.CryptographicParameters.Q;
    private static readonly BigInteger G = EGParameters.CryptographicParameters.G;

    public static TheoryData<string> RoundTripValues =>
    [
        "0",
        "1",
        "2",
        "P-1",
        "P-2",
        "G",
    ];

    [Theory]
    [MemberData(nameof(RoundTripValues))]
    public void ToMontgomeryAndBack_PreservesValue(string which)
    {
        BigInteger value = Resolve(which);
        IntegerModP original = new(value);

        IntegerModP roundTripped = MontgomeryModP.RoundTrip(original);

        Assert.Equal(original, roundTripped);
    }

    [Fact]
    public void Multiply_MatchesModularMultiplication()
    {
        Random random = new(20260920);

        for (int i = 0; i < 25; i++)
        {
            BigInteger a = RandomBelowP(random);
            BigInteger b = RandomBelowP(random);

            IntegerModP product = MontgomeryModP.MultiplyMod(new IntegerModP(a), new IntegerModP(b));

            Assert.Equal(new IntegerModP(a * b % P), product);
        }
    }

    [Fact]
    public void Multiply_AtTheTopOfTheRange_StillReduces()
    {
        // (p-1)^2 is the largest product the CIOS running sum ever has to hold. With p filling its
        // top limb this is exactly the case that needs the extra limb and the final subtraction.
        IntegerModP max = new(P - 1);

        IntegerModP squared = MontgomeryModP.SquareMod(max);

        Assert.Equal(new IntegerModP((P - 1) * (P - 1) % P), squared);
    }

    [Fact]
    public void Square_MatchesMultiplyingByItself()
    {
        IntegerModP g = new(G);

        Assert.Equal(MontgomeryModP.MultiplyMod(g, g), MontgomeryModP.SquareMod(g));
    }

    [Fact]
    public void Multiply_ByMontgomeryOne_IsIdentity()
    {
        Assert.Equal(
            new IntegerModP(G),
            MontgomeryModP.MultiplyMod(new IntegerModP(G), new IntegerModP(BigInteger.One)));
    }

    [Fact]
    public void PowModP_MatchesIntegerModP_ForRandomExponents()
    {
        Random random = new(4096);

        for (int i = 0; i < 10; i++)
        {
            IntegerModQ exponent = new(RandomBelowQ(random));

            IntegerModP expected = IntegerModP.PowModP(G, exponent);
            IntegerModP actual = MontgomeryModP.PowModP(G, exponent);

            Assert.Equal(expected, actual);
        }
    }

    [Fact]
    public void PowModP_ExponentZero_IsOne()
    {
        Assert.Equal(new IntegerModP(BigInteger.One), MontgomeryModP.PowModP(G, new IntegerModQ(BigInteger.Zero)));
    }

    [Fact]
    public void PowModP_ExponentOne_IsTheBase()
    {
        Assert.Equal(new IntegerModP(G), MontgomeryModP.PowModP(G, new IntegerModQ(BigInteger.One)));
    }

    [Fact]
    public void PowModP_LargestExponent_MatchesIntegerModP()
    {
        // q-1 exercises every window of the exponent, including the most significant one.
        IntegerModQ exponent = new(Q - 1);

        Assert.Equal(IntegerModP.PowModP(G, exponent), MontgomeryModP.PowModP(G, exponent));
    }

    [Fact]
    public void PowModP_BaseOne_IsOne()
    {
        IntegerModQ exponent = new(RandomBelowQ(new Random(7)));

        Assert.Equal(new IntegerModP(BigInteger.One), MontgomeryModP.PowModP(BigInteger.One, exponent));
    }

    [Fact]
    public void PowModP_ArbitraryBase_MatchesIntegerModP()
    {
        // Bases other than g and K never have tables, so this is the table-free path specifically.
        Random random = new(31337);
        BigInteger basis = RandomBelowP(random);
        IntegerModQ exponent = new(RandomBelowQ(random));

        Assert.Equal(IntegerModP.PowModP(basis, exponent), MontgomeryModP.PowModP(basis, exponent));
    }

    [Fact]
    public void PowModP_ResultIsInTheSubgroupOfOrderQ()
    {
        // g generates the order-q subgroup (§3.1.1), so any power of it must satisfy x^q = 1.
        IntegerModQ exponent = new(RandomBelowQ(new Random(99)));

        IntegerModP result = MontgomeryModP.PowModP(G, exponent);

        Assert.Equal(new IntegerModP(BigInteger.One), IntegerModP.PowModP(result, Q));
    }

    [Fact]
    public void PowModP_BigIntegerExponent_MatchesIntegerModP()
    {
        Random random = new(616);
        BigInteger basis = RandomBelowP(random);

        // An exponent that is deliberately not an element of Z_q.
        BigInteger exponent = Q + 12345;

        Assert.Equal(IntegerModP.PowModP(basis, exponent), MontgomeryModP.PowModP(basis, exponent));
    }

    [Fact]
    public void PowModP_RaisingToQ_DistinguishesSubgroupMembership()
    {
        // The subgroup checks of Verifications 2, 6 and 7 are "x^q mod p = 1". The exponent is q
        // itself, so it must travel as a BigInteger: reducing it into Z_q would make it zero and
        // turn the check into "x^0 = 1", which every value passes. This test fails loudly if that
        // ever happens, because the two cases below would stop differing.
        IntegerModP inSubgroup = MontgomeryModP.PowModP(G, new IntegerModQ(RandomBelowQ(new Random(11))));
        IntegerModP outsideSubgroup = new(new BigInteger(2));

        Assert.Equal(new IntegerModP(BigInteger.One), MontgomeryModP.PowModP(inSubgroup, Q));
        Assert.NotEqual(new IntegerModP(BigInteger.One), MontgomeryModP.PowModP(outsideSubgroup, Q));
    }

    [Fact]
    public void PowModP_BigIntegerExponent_IgnoresPrecomputedTables()
    {
        // A table is sized to Z_q exponents. Even with g tabled, an exponent of q must not be
        // answered from it.
        PowRadixRegistry.Clear();
        try
        {
            PowRadixRegistry.Precompute(4, G);

            Assert.Equal(IntegerModP.PowModP(G, Q), MontgomeryModP.PowModP(G, Q));
        }
        finally
        {
            PowRadixRegistry.Clear();
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(9)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(65535)]
    [InlineData(int.MaxValue)]
    public void PowModP_ShortExponents_MatchIntegerModP(int exponent)
    {
        // Short exponents take a 1-bit window rather than the 4-bit one, so these cover a code path
        // that the full-width Z_q cases never reach, including both sides of the width threshold.
        BigInteger basis = RandomBelowP(new Random(exponent));

        Assert.Equal(
            IntegerModP.PowModP(basis, new BigInteger(exponent)),
            MontgomeryModP.PowModP(basis, new BigInteger(exponent)));
    }

    [Fact]
    public void PowModP_EitherWindowWidth_AgreesWithTheOther()
    {
        // An exponent just above the narrow-window threshold and the same value padded into Z_q
        // take different widths internally and must still agree.
        BigInteger value = new(0x0123456789ABCDEF);

        Assert.Equal(
            MontgomeryModP.PowModP(G, value),
            MontgomeryModP.PowModP(G, new IntegerModQ(value)));
    }

    [Fact]
    public void PowModP_NegativeExponent_IsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => MontgomeryModP.PowModP(G, new BigInteger(-1)));
    }

    [Fact]
    public void PowModP_BigIntegerExponentZero_IsOne()
    {
        Assert.Equal(new IntegerModP(BigInteger.One), MontgomeryModP.PowModP(G, BigInteger.Zero));
    }

    private static BigInteger Resolve(string which) => which switch
    {
        "0" => BigInteger.Zero,
        "1" => BigInteger.One,
        "2" => new BigInteger(2),
        "P-1" => P - 1,
        "P-2" => P - 2,
        "G" => G,
        _ => throw new ArgumentOutOfRangeException(nameof(which), which, null),
    };

    internal static BigInteger RandomBelowP(Random random)
    {
        byte[] bytes = new byte[512];
        random.NextBytes(bytes);
        return new BigInteger(bytes, isUnsigned: true, isBigEndian: true) % P;
    }

    internal static BigInteger RandomBelowQ(Random random)
    {
        byte[] bytes = new byte[32];
        random.NextBytes(bytes);
        return new BigInteger(bytes, isUnsigned: true, isBigEndian: true) % Q;
    }
}
