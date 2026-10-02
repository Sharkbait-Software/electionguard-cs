using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Crypto;

public class MontgomeryContextTests
{
    public MontgomeryContextTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static readonly BigInteger P = EGParameters.CryptographicParameters.P;

    [Fact]
    public void Current_UsesActiveModulus()
    {
        MontgomeryContext context = MontgomeryContext.Current;

        Assert.Equal(P, context.Modulus);
    }

    [Fact]
    public void LimbCount_CoversTheSpecs4096BitPrime()
    {
        // §3.1.1: p is 4096 bits, which is exactly 64 64-bit limbs with no spare high bits. The
        // absence of spare bits is why the CIOS running sum needs its extra limb.
        Assert.Equal(4096, P.GetBitLength());
        Assert.Equal(64, MontgomeryContext.Current.LimbCount);
    }

    [Fact]
    public void For_SameModulus_ReturnsCachedInstance()
    {
        MontgomeryContext first = MontgomeryContext.For(P);
        MontgomeryContext second = MontgomeryContext.For(P);

        Assert.Same(first, second);
    }

    [Fact]
    public void For_DifferentModulus_BuildsDistinctContext()
    {
        MontgomeryContext small = MontgomeryContext.For(new BigInteger(101));

        Assert.Equal(new BigInteger(101), small.Modulus);
        Assert.Equal(1, small.LimbCount);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(-7)]
    public void For_RejectsModulusWithoutAnInverseModR(int modulus)
    {
        // Montgomery reduction requires gcd(p, R) = 1 with R a power of two, so p must be odd and
        // positive.
        Assert.Throws<ArgumentException>(() => MontgomeryContext.For(new BigInteger(modulus)));
    }

    [Fact]
    public void For_SmallOddModulus_MultipliesCorrectly()
    {
        // Exercises the limb code at a size where every intermediate is checkable by hand.
        using (EGParameters.OverrideScope(SmallParameters(), new GuardianParameters()))
        {
            Assert.Equal(
                new IntegerModP(new BigInteger(77 % 101)),
                MontgomeryModP.MultiplyMod(new IntegerModP(new BigInteger(7)), new IntegerModP(new BigInteger(11))));
        }
    }

    [Fact]
    public void For_SmallOddModulus_SquaresCorrectly()
    {
        // A one-limb modulus leaves Square with no cross products at all, which is the edge of its
        // row loop.
        using (EGParameters.OverrideScope(SmallParameters(), new GuardianParameters()))
        {
            for (int a = 0; a < 101; a++)
            {
                Assert.Equal(
                    new IntegerModP(new BigInteger(a * a % 101)),
                    MontgomeryModP.SquareMod(new IntegerModP(new BigInteger(a))));
            }
        }
    }

    [Fact]
    public void LimbConversion_WriteAndRead_AreInverses()
    {
        int limbCount = MontgomeryContext.Current.LimbCount;
        Random random = new(1);

        foreach (BigInteger value in new[]
        {
            BigInteger.Zero,
            BigInteger.One,
            new BigInteger(2),
            P - 1,
            P / 2,
            EGParameters.CryptographicParameters.G,
            ((BigInteger.One << 64) - 1) % P,
            (BigInteger.One << 64) % P,
            ((BigInteger.One << 4032) - 1) % P,
            RandomBelowP(random),
            RandomBelowP(random),
        })
        {
            ulong[] limbs = new ulong[limbCount];
            MontgomeryContext.WriteLimbs(value, limbs);

            Assert.Equal(value, MontgomeryContext.FromLimbs(limbs));
            Assert.Equal(new IntegerModP(value), MontgomeryModP.RoundTrip(new IntegerModP(value)));
        }
    }

    [Fact]
    public void LimbConversion_LimbZeroIsLeastSignificant()
    {
        int limbCount = MontgomeryContext.Current.LimbCount;
        BigInteger value = (new BigInteger(0x1122334455667788UL) << 64) | 0x0102030405060708UL;

        ulong[] limbs = new ulong[limbCount];
        MontgomeryContext.WriteLimbs(value, limbs);

        Assert.Equal(0x0102030405060708UL, limbs[0]);
        Assert.Equal(0x1122334455667788UL, limbs[1]);
        Assert.All(limbs[2..], limb => Assert.Equal(0UL, limb));
    }

    private static BigInteger RandomBelowP(Random random)
    {
        byte[] bytes = new byte[512];
        random.NextBytes(bytes);
        return new BigInteger(bytes, isUnsigned: true, isBigEndian: true) % P;
    }

    private static CryptographicParameters SmallParameters()
    {
        return new CryptographicParameters(
            CryptographicParameters.VERSION_DEFAULT,
            q: "0D",
            p: "65",
            r: "01",
            g: "02");
    }
}
