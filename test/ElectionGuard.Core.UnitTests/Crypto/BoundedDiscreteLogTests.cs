using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Crypto;

/// <summary>
/// <see cref="BoundedDiscreteLog"/>: baby-step giant-step over [0, maxExponent]. The cases sweep
/// every exponent of small ranges, so that each one is found through every combination of giant step
/// and baby step, including both ends of the range, and the step sizes from one (all giant steps) to
/// the whole range (one table lookup).
///
/// Each case runs on both engines; see <see cref="ModPProductTests"/>.
/// </summary>
public class BoundedDiscreteLogTests
{
    public BoundedDiscreteLogTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static readonly BigInteger P = EGParameters.CryptographicParameters.P;

    /// <summary>A stand-in for K: any element of the order-q subgroup will do.</summary>
    private static readonly IntegerModP Basis = new(BigInteger.ModPow(EGParameters.CryptographicParameters.G, 123456789, P));

    public static TheoryData<int, int, bool> RangesAndEngines()
    {
        TheoryData<int, int, bool> data = new();
        foreach (var (maxExponent, lookups) in new[] { (0, 1), (1, 1), (2, 2), (10, 1), (10, 1000), (37, 3), (100, 75) })
        {
            data.Add(maxExponent, lookups, true);
            data.Add(maxExponent, lookups, false);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(RangesAndEngines))]
    public void TryFind_EveryExponentInRange_IsFound(int maxExponent, int expectedLookups, bool allowAvx512)
    {
        BoundedDiscreteLog log = new(Basis, maxExponent, expectedLookups, allowAvx512);

        for (int exponent = 0; exponent <= maxExponent; exponent++)
        {
            IntegerModP target = new(BigInteger.ModPow(Basis.ToBigInteger(), exponent, P));

            Assert.True(log.TryFind(target, out int found), $"exponent {exponent} not found");
            Assert.Equal(exponent, found);
        }
    }

    [Theory]
    [MemberData(nameof(RangesAndEngines))]
    public void TryFind_ExponentJustAboveRange_IsNotFound(int maxExponent, int expectedLookups, bool allowAvx512)
    {
        BoundedDiscreteLog log = new(Basis, maxExponent, expectedLookups, allowAvx512);

        // Above the bound but possibly inside the last giant step's window: must still be rejected.
        for (int exponent = maxExponent + 1; exponent <= maxExponent + log.Step + 1; exponent++)
        {
            IntegerModP target = new(BigInteger.ModPow(Basis.ToBigInteger(), exponent, P));

            Assert.False(log.TryFind(target, out int found), $"exponent {exponent} wrongly found as {found}");
            Assert.Equal(-1, found);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void TryFind_ValueOutsideTheSubgroup_IsNotFound(bool allowAvx512)
    {
        BoundedDiscreteLog log = new(Basis, 1000, 10, allowAvx512);

        Assert.False(log.TryFind(new IntegerModP(P - 1), out _));
        Assert.False(log.TryFind(new IntegerModP(0), out _));
    }

    [Fact]
    public void Step_BalancesTableAgainstLookups()
    {
        // sqrt(lookups * candidates), clamped to [1, candidates].
        Assert.Equal(1, new BoundedDiscreteLog(Basis, 0, 1).Step);
        Assert.Equal(32, new BoundedDiscreteLog(Basis, 1000, 1).Step);
        Assert.Equal(274, new BoundedDiscreteLog(Basis, 1000, 75).Step);
        Assert.Equal(1001, new BoundedDiscreteLog(Basis, 1000, 1_000_000).Step);
    }

    [Fact]
    public void Constructor_ZeroBasis_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new BoundedDiscreteLog(new IntegerModP(0), 10, 1));
    }

    [Fact]
    public void Constructor_NegativeMaxExponent_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new BoundedDiscreteLog(Basis, -1, 1));
    }

    [Fact]
    public void TryFind_CalledConcurrently_FindsEveryExponent()
    {
        BoundedDiscreteLog log = new(Basis, 500, 64);
        var found = new int[64];

        Parallel.For(0, found.Length, i =>
        {
            IntegerModP target = new(BigInteger.ModPow(Basis.ToBigInteger(), i * 7, P));
            found[i] = log.TryFind(target, out int exponent) ? exponent : -1;
        });

        for (int i = 0; i < found.Length; i++)
        {
            Assert.Equal(i * 7, found[i]);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void SmallNonSpecModulus_FindsSmallestExponent(bool allowAvx512)
    {
        // 4 has order 11 mod 23, so exponents in [0, 30] repeat; the search reports the smallest.
        CryptographicParameters small = new(CryptographicParameters.VERSION_DEFAULT, q: "0B", p: "17", r: "02", g: "04");
        using (EGParameters.OverrideScope(small, new GuardianParameters()))
        {
            BoundedDiscreteLog log = new(new IntegerModP(4), 30, 2, allowAvx512);

            for (int exponent = 0; exponent <= 30; exponent++)
            {
                Assert.True(log.TryFind(new IntegerModP(BigInteger.ModPow(4, exponent, 23)), out int found));
                Assert.Equal(exponent % 11, found);
            }

            // 5 is not a power of 4 mod 23.
            Assert.False(log.TryFind(new IntegerModP(5), out _));
        }
    }
}
