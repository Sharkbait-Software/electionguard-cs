using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Crypto;

public class SubgroupMembershipTests
{
    public SubgroupMembershipTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static readonly BigInteger P = EGParameters.CryptographicParameters.P;
    private static readonly BigInteger Q = EGParameters.CryptographicParameters.Q;

    /// <summary>
    /// The batch test's soundness argument (see SubgroupMembership) rests on p - 1 = 2 * q * r'
    /// with q and r' odd primes and r' much larger than 2^128. That is a property of the spec's
    /// constants, not of the code, so it is pinned here: if the parameters ever change, this fails
    /// before a weaker batch test silently ships.
    /// </summary>
    [Fact]
    public void SpecParameters_HaveTheCofactorStructureTheBatchTestRequires()
    {
        BigInteger r = EGParameters.CryptographicParameters.R;

        Assert.Equal(P - 1, Q * r);
        Assert.True(r.IsEven);

        BigInteger rPrime = r / 2;
        Assert.False(rPrime.IsEven);
        Assert.True(rPrime.GetBitLength() > SubgroupMembership.BatchExponentBits);
        Assert.True(IsProbablePrime(rPrime));
        Assert.True(IsProbablePrime(Q));
        Assert.True(SubgroupMembership.BatchingIsSoundForActiveParameters());
    }

    [Fact]
    public void Jacobi_MatchesEulersCriterion()
    {
        // For prime p, (x / p) = x^((p-1)/2) mod p, read as 1, p - 1 (meaning -1) or 0.
        Random random = new(20260932);
        List<BigInteger> values = [BigInteger.Zero, BigInteger.One, new BigInteger(2), new BigInteger(3), P - 1, P - 2];
        for (int i = 0; i < 60; i++)
        {
            values.Add(MontgomeryModPTests.RandomBelowP(random));
        }

        MontgomeryContext context = MontgomeryContext.Current;
        foreach (BigInteger value in values)
        {
            BigInteger euler = BigInteger.ModPow(value, (P - 1) / 2, P);
            int expected = euler.IsZero ? 0 : euler.IsOne ? 1 : -1;

            Assert.Equal(expected, SubgroupMembership.Jacobi(value, context));
        }
    }

    [Fact]
    public void Jacobi_MatchesReferenceForSmallOddModuli()
    {
        // Composite moduli too, which exercise the gcd > 1 (symbol 0) exit and reciprocity between
        // operands that are not prime. For those the divsteps never reach f = 1, so this also
        // drives the fallback to the binary algorithm.
        for (int n = 1; n < 200; n += 2)
        {
            for (int a = 0; a < n; a++)
            {
                Span<ulong> x = [(ulong)a];
                Span<ulong> y = [(ulong)n];

                Assert.Equal(ReferenceJacobi(a, n), SubgroupMembership.Jacobi(x, y));
            }
        }
    }

    [Fact]
    public void JacobiBinary_MatchesReferenceForSmallOddModuli()
    {
        // The fallback on its own, since for coprime inputs Jacobi never reaches it.
        for (int n = 1; n < 200; n += 2)
        {
            for (int a = 0; a < n; a++)
            {
                Span<ulong> x = [(ulong)a];
                Span<ulong> y = [(ulong)n];

                Assert.Equal(ReferenceJacobi(a, n), SubgroupMembership.JacobiBinary(x, y));
            }
        }
    }

    [Fact]
    public void TryJacobiDivsteps_ConvergesAndMatchesEulersCriterion_AtFullWidth()
    {
        // The divsteps have no proven step bound, so this pins that they converge (rather than
        // silently handing every value to the slow fallback) and agree with Euler's criterion, on
        // full-width values. Squares and negated squares guarantee both signs are covered, and
        // limb-boundary shapes exercise the length shrinking.
        Random random = new(20261001);
        MontgomeryContext context = MontgomeryContext.Current;
        List<BigInteger> values = [BigInteger.One, new BigInteger(2), P - 1, P - 2, (BigInteger.One << 64) - 1, BigInteger.One << 4000];
        for (int i = 0; i < 100; i++)
        {
            BigInteger r = MontgomeryModPTests.RandomBelowP(random);
            values.Add(r);
            values.Add(r * r % P);
            values.Add(P - r * r % P);
        }

        ulong[] x = new ulong[context.LimbCount];
        foreach (BigInteger value in values.Where(v => !v.IsZero))
        {
            MontgomeryContext.WriteLimbs(value, x, !BitConverter.IsLittleEndian);

            Assert.True(SubgroupMembership.TryJacobiDivsteps(x, context.ModulusLimbs, out int symbol));

            BigInteger euler = BigInteger.ModPow(value, (P - 1) / 2, P);
            Assert.Equal(euler.IsOne ? 1 : -1, symbol);
        }
    }

    [Fact]
    public void TryJacobiDivsteps_Composite_DoesNotConverge_AndLeavesInputsUntouched()
    {
        // gcd(21, 35) = 7, so f can never reach 1. The method must give up rather than report a
        // symbol, and must not have consumed the inputs the fallback is about to read.
        ulong[] x = [21];
        ulong[] y = [35];

        Assert.False(SubgroupMembership.TryJacobiDivsteps(x, y, out _));
        Assert.Equal([21UL], x);
        Assert.Equal([35UL], y);
        Assert.Equal(0, SubgroupMembership.Jacobi(x, y));
    }

    [Fact]
    public void IndexOfFirstNonMember_AllMembers_ReturnsMinusOne()
    {
        List<IntegerModP> members = Members(40);

        Assert.Equal(-1, SubgroupMembership.IndexOfFirstNonMember(members));
    }

    public static TheoryData<string> NonMemberKinds => ["zero", "two", "minusOne", "negatedMember"];

    /// <summary>
    /// "two" is a quadratic residue (p = 7 mod 8) outside the subgroup, so only the batch
    /// exponentiation can reject it. "minusOne" and "negatedMember" are non-residues, rejected by the
    /// Jacobi symbol. Together they reach both halves of the test.
    /// </summary>
    [Theory]
    [MemberData(nameof(NonMemberKinds))]
    public void IndexOfFirstNonMember_FindsTheNonMember(string kind)
    {
        List<IntegerModP> values = Members(20);
        IntegerModP nonMember = kind switch
        {
            "zero" => new IntegerModP(0),
            "two" => new IntegerModP(2),
            "minusOne" => new IntegerModP(P - 1),
            "negatedMember" => new IntegerModP(P - values[3].ToBigInteger()),
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };
        Assert.False(SubgroupMembership.IsMember(nonMember));

        values[13] = nonMember;

        Assert.Equal(13, SubgroupMembership.IndexOfFirstNonMember(values));
    }

    [Fact]
    public void IndexOfFirstNonMember_NonMembersWhoseProductIsAMember_AreStillCaught()
    {
        // 2 and 2^-1 are both outside the subgroup but multiply to 1, so a test that merely
        // multiplied the values together would accept them. The random exponents are what stop
        // the two from cancelling.
        BigInteger two = new(2);
        BigInteger inverse = BigInteger.ModPow(two, P - 2, P);

        List<IntegerModP> values = Members(10);
        values[4] = new IntegerModP(two);
        values[7] = new IntegerModP(inverse);

        Assert.Equal(4, SubgroupMembership.IndexOfFirstNonMember(values));
    }

    [Fact]
    public void IndexOfFirstNonMember_ReportsTheFirstOfSeveral()
    {
        // The later value fails the Jacobi check, the earlier one only the batch test; the earlier
        // one must still be the one reported.
        List<IntegerModP> values = Members(10);
        values[2] = new IntegerModP(2);
        values[6] = new IntegerModP(P - 1);

        Assert.Equal(2, SubgroupMembership.IndexOfFirstNonMember(values));
    }

    [Fact]
    public void IndexOfFirstNonMember_NonSpecParameters_UsesTheExactTest()
    {
        // p = 23, q = 11, r = 2: the subgroup is the quadratic residues mod 23. The batch test is
        // only justified for the spec's parameters, so this must fall back, and still be correct.
        CryptographicParameters small = new(CryptographicParameters.VERSION_DEFAULT, q: "0B", p: "17", r: "02", g: "04");
        HashSet<int> residues = [1, 2, 3, 4, 6, 8, 9, 12, 13, 16, 18];

        using (EGParameters.OverrideScope(small, new GuardianParameters()))
        {
            Assert.False(SubgroupMembership.BatchingIsSoundForActiveParameters());

            for (int candidate = 0; candidate < 23; candidate++)
            {
                List<IntegerModP> values = [new IntegerModP(4), new IntegerModP(candidate), new IntegerModP(9)];
                int expected = residues.Contains(candidate) ? -1 : 1;

                Assert.Equal(expected, SubgroupMembership.IndexOfFirstNonMember(values));
            }
        }
    }

    private static List<IntegerModP> Members(int count)
    {
        return Enumerable.Range(0, count)
            .Select(_ => MontgomeryModP.PowModP(EGParameters.G, ElectionGuardRandom.GetIntegerModQ()))
            .ToList();
    }

    private static int ReferenceJacobi(int a, int n)
    {
        a %= n;
        int result = 1;
        while (a != 0)
        {
            while (a % 2 == 0)
            {
                a /= 2;
                if (n % 8 == 3 || n % 8 == 5)
                {
                    result = -result;
                }
            }

            (a, n) = (n, a);
            if (a % 4 == 3 && n % 4 == 3)
            {
                result = -result;
            }

            a %= n;
        }

        return n == 1 ? result : 0;
    }

    private static bool IsProbablePrime(BigInteger n)
    {
        BigInteger d = n - 1;
        int s = 0;
        while (d.IsEven)
        {
            d >>= 1;
            s++;
        }

        // Fixed small-prime bases: deterministic, and far more than enough for a sanity pin.
        foreach (int a in new[] { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29 })
        {
            BigInteger x = BigInteger.ModPow(a, d, n);
            if (x.IsOne || x == n - 1)
            {
                continue;
            }

            bool composite = true;
            for (int i = 1; i < s; i++)
            {
                x = BigInteger.ModPow(x, 2, n);
                if (x == n - 1)
                {
                    composite = false;
                    break;
                }
            }

            if (composite)
            {
                return false;
            }
        }

        return true;
    }
}
