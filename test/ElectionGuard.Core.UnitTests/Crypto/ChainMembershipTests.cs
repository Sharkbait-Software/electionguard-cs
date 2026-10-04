using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Crypto;

/// <summary>
/// The exact Z_p^r membership test that rides on the variable-time exponentiation's squaring chain:
/// x^q = 1 exactly when x^(2^t) = x^c, for q = 2^t - c and x invertible. Checked against the
/// definition, x^q mod p = 1 with 0 &lt; x &lt; p, on both engines, and with the exponentiation's
/// results checked against ModPow at the same time, since the two share one walk.
/// </summary>
public class ChainMembershipTests
{
    public ChainMembershipTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static readonly BigInteger P = EGParameters.CryptographicParameters.P;
    private static readonly BigInteger Q = EGParameters.CryptographicParameters.Q;
    private static readonly BigInteger G = EGParameters.CryptographicParameters.G;

    public static TheoryData<bool> Engines => new() { true, false };

    [Fact]
    public void SpecQ_HasTheShapeTheCheckNeeds()
    {
        Assert.True(MontgomeryModP.TryGetChainMembershipShape(out MontgomeryModP.ChainMembershipShape shape));
        Assert.Equal(256, shape.PowerOfTwo);
        Assert.Equal(189UL, shape.Remainder);
        Assert.Equal(Q, (BigInteger.One << shape.PowerOfTwo) - shape.Remainder);
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void Members_AreAccepted_AndPowersMatchModPow(bool allowAvx512)
    {
        Random random = new(1);
        BigInteger[] members = [BigInteger.One, G, BigInteger.ModPow(G, MontgomeryModPTests.RandomBelowQ(random), P), BigInteger.ModPow(G, Q - 1, P)];
        foreach (BigInteger member in members)
        {
            Assert.True(Check(member, allowAvx512, random), $"rejected member {member}");
        }
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void NonMembers_AreRejected_AndPowersStillMatchModPow(bool allowAvx512)
    {
        // 0 satisfies the identity x^(2^t) = x^c and must be excluded separately; 2 is a quadratic
        // residue outside the subgroup; p - 1 has order 2; the last is a member times p - 1.
        Random random = new(2);
        BigInteger member = BigInteger.ModPow(G, MontgomeryModPTests.RandomBelowQ(random), P);
        BigInteger[] nonMembers = [BigInteger.Zero, new BigInteger(2), P - 1, member * (P - 1) % P, MontgomeryModPTests.RandomBelowP(random)];
        foreach (BigInteger nonMember in nonMembers)
        {
            Assert.False(Check(nonMember, allowAvx512, random), $"accepted non-member {nonMember}");
        }
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void ZeroAndShortExponents_StillWalkTheWholeChain(bool allowAvx512)
    {
        // The chain must reach 2^t for the membership test even when no exponent needs it to.
        Random random = new(3);
        BigInteger member = BigInteger.ModPow(G, MontgomeryModPTests.RandomBelowQ(random), P);
        foreach (BigInteger[] exponents in new[] { new[] { BigInteger.Zero }, new[] { BigInteger.One }, new[] { new BigInteger(5), BigInteger.Zero } })
        {
            Assert.True(Check(member, allowAvx512, exponents));
            Assert.False(Check(new BigInteger(2), allowAvx512, exponents));
        }
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void TinyParameters_MatchTheDefinitionForEveryResidue(bool allowAvx512)
    {
        // q = 11 = 2^4 - 5, p = 23: every residue, so both outcomes and 0 are all exercised.
        CryptographicParameters small = new(CryptographicParameters.VERSION_DEFAULT, q: "0B", p: "17", r: "02", g: "04");
        using (EGParameters.OverrideScope(small, new GuardianParameters()))
        {
            Assert.True(MontgomeryModP.TryGetChainMembershipShape(out MontgomeryModP.ChainMembershipShape shape));
            Assert.Equal(4, shape.PowerOfTwo);
            Assert.Equal(5UL, shape.Remainder);

            for (int x = 0; x < 23; x++)
            {
                bool expected = x != 0 && BigInteger.ModPow(x, 11, 23) == 1;
                Assert.Equal(expected, Check(new BigInteger(x), allowAvx512, [new BigInteger(7), new BigInteger(10)]));
            }
        }
    }

    [Fact]
    public void QWithManySetBitsInItsRemainder_IsNotOffered()
    {
        // Each set bit of c costs a multiply per base, so a q whose remainder is dense, such as
        // 2^256 - (2^200 - 1), is refused and callers use the separate subgroup test instead.
        BigInteger denseQ = (BigInteger.One << 256) - ((BigInteger.One << 200) - 1);
        CryptographicParameters dense = new(CryptographicParameters.VERSION_DEFAULT, q: Hex(denseQ), p: "17", r: "02", g: "04");
        using (EGParameters.OverrideScope(dense, new GuardianParameters()))
        {
            Assert.False(MontgomeryModP.TryGetChainMembershipShape(out _));
        }
    }

    private static string Hex(BigInteger value) => Convert.ToHexString(value.ToByteArray(isUnsigned: true, isBigEndian: true));

    private static bool Check(BigInteger basis, bool allowAvx512, Random random)
    {
        return Check(basis, allowAvx512, [MontgomeryModPTests.RandomBelowQ(random), MontgomeryModPTests.RandomBelowQ(random)]);
    }

    /// <summary>
    /// Runs the membership-checking exponentiation on the chosen engine, asserts its powers against
    /// ModPow, and returns its membership verdict after asserting it against the definition.
    /// </summary>
    private static bool Check(BigInteger basis, bool allowAvx512, BigInteger[] exponentValues)
    {
        IntegerModQ[] exponents = exponentValues.Select(e => new IntegerModQ(e)).ToArray();
        BigInteger p = EGParameters.P;
        bool expected = basis > 0 && basis < p && BigInteger.ModPow(basis, EGParameters.Q, p) == 1;

        bool verdict;
        BigInteger[] powers = new BigInteger[exponents.Length];
        if (allowAvx512 && Avx512Montgomery.TryGetCurrent(out Avx512Montgomery engine))
        {
            var arithmetic = new Avx512MontgomeryArithmetic(engine);
            ulong[] results = new ulong[exponents.Length * arithmetic.Width];
            verdict = MontgomeryModP.PowVariableTimeMontgomeryCheckingMembership(new IntegerModP(basis), exponents, results, arithmetic);
            for (int k = 0; k < exponents.Length; k++)
            {
                powers[k] = arithmetic.FromMontgomery(results.AsSpan(k * arithmetic.Width, arithmetic.Width));
            }
        }
        else
        {
            var arithmetic = new ScalarMontgomeryArithmetic(MontgomeryContext.Current);
            ulong[] results = new ulong[exponents.Length * arithmetic.Width];
            verdict = MontgomeryModP.PowVariableTimeMontgomeryCheckingMembership(new IntegerModP(basis), exponents, results, arithmetic);
            for (int k = 0; k < exponents.Length; k++)
            {
                powers[k] = arithmetic.FromMontgomery(results.AsSpan(k * arithmetic.Width, arithmetic.Width));
            }
        }

        for (int k = 0; k < exponents.Length; k++)
        {
            Assert.Equal(BigInteger.ModPow(basis, exponents[k].ToBigInteger(), p), powers[k]);
        }

        Assert.Equal(expected, verdict);
        return verdict;
    }
}
