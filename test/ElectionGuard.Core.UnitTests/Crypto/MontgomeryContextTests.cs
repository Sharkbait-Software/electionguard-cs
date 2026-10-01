using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Buffers.Binary;
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

    /// <summary>
    /// The limb conversions are the only byte-order-sensitive code in the Montgomery arithmetic, and
    /// the big-endian branch would otherwise ship without ever having run, since every machine this
    /// is developed and tested on is little-endian.
    ///
    /// Note what running the swap on a little-endian machine does and does not show. It does not
    /// simulate a big-endian host: there the swap compensates for the host reading each limb's bytes
    /// in the opposite order, whereas here it simply byte-reverses limbs that were already correct.
    /// What it does show is that the write and the read agree, which is the mistake actually
    /// available to make -- swapping on one side and forgetting on the other.
    /// </summary>
    public static TheoryData<bool> BothSwapSettings => [false, true];

    [Theory]
    [MemberData(nameof(BothSwapSettings))]
    public void LimbConversion_WriteAndRead_AreInversesUnderEitherSwapSetting(bool swapLimbBytes)
    {
        int limbCount = MontgomeryContext.Current.LimbCount;
        Random random = new(swapLimbBytes ? 1 : 2);

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
            MontgomeryContext.WriteLimbs(value, limbs, swapLimbBytes);

            Assert.Equal(value, MontgomeryContext.FromLimbs(limbs, swapLimbBytes));
        }
    }

    [Fact]
    public void LimbConversion_BigEndianHost_DiffersFromLittleEndianByExactlyAPerLimbByteSwap()
    {
        // This is the property that makes the big-endian path correct rather than merely
        // self-consistent. A big-endian host reinterprets each limb's bytes in the opposite order, so
        // compensating for it must be exactly a per-limb reversal and nothing else -- not a reversal
        // of the whole buffer, which would also reverse the order of the limbs themselves.
        int limbCount = MontgomeryContext.Current.LimbCount;
        BigInteger value = RandomBelowP(new Random(31415));

        ulong[] littleEndian = new ulong[limbCount];
        ulong[] bigEndian = new ulong[limbCount];
        MontgomeryContext.WriteLimbs(value, littleEndian, swapLimbBytes: false);
        MontgomeryContext.WriteLimbs(value, bigEndian, swapLimbBytes: true);

        for (int i = 0; i < limbCount; i++)
        {
            Assert.Equal(BinaryPrimitives.ReverseEndianness(littleEndian[i]), bigEndian[i]);
        }
    }

    [Fact]
    public void LimbConversion_DefaultOverloads_FollowTheActualHost()
    {
        // Ties the explicitly-driven conversions above to the ones production actually calls. Writing
        // with the flag this host needs must be readable by the overload that chooses for itself, and
        // the full path through ToMontgomery/FromMontgomery -- which uses only the parameterless
        // overloads -- must agree. Without this, the theory above could be self-consistent while
        // production took a different branch.
        int limbCount = MontgomeryContext.Current.LimbCount;
        BigInteger value = RandomBelowP(new Random(2718));

        ulong[] limbs = new ulong[limbCount];
        MontgomeryContext.WriteLimbs(value, limbs, swapLimbBytes: !BitConverter.IsLittleEndian);

        Assert.Equal(value, MontgomeryContext.FromLimbs(limbs));
        Assert.Equal(new IntegerModP(value), MontgomeryModP.RoundTrip(new IntegerModP(value)));
    }

    [Fact]
    public void Construction_DoesNotRequireALittleEndianHost()
    {
        // An earlier version refused to construct anywhere but little-endian. The limb conversions
        // now handle either, so the restriction is gone; this records that it should stay gone.
        Assert.Equal(P, MontgomeryContext.Current.Modulus);
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
