using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Crypto;

/// <summary>
/// Drives <see cref="MontgomeryContext.Multiply"/> and <see cref="MontgomeryContext.Square"/> on raw
/// limbs, checking each against the definition a * b * R^-1 mod p computed with BigInteger.
///
/// <see cref="MontgomeryAdversarialTests"/> reaches the kernels through ToMontgomery, so the limbs
/// that actually arrive there are Montgomery forms of its shaped values, which look random. Here the
/// carry-heavy shapes are the kernel inputs themselves: all-ones limbs, p - 1, values just below R.
///
/// It also covers moduli other than the spec's p. Multiply fuses each product row with its reduction
/// row, and Square walks its rows two at a time with an odd row left over, so limb counts of 1, 2, 3
/// and odd and even sizes each take a different path through the loops; the spec's 64-limb p only
/// ever takes one of them. A modulus with a small top limb leaves the overflow limb a different job
/// than the spec's p, whose top limb is all ones.
/// </summary>
public class MontgomeryKernelTests
{
    public MontgomeryKernelTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static IEnumerable<BigInteger> Moduli()
    {
        Random random = new(20261001);

        yield return EGParameters.CryptographicParameters.P;
        yield return new BigInteger(101);
        yield return ulong.MaxValue;

        foreach (int limbs in new[] { 1, 2, 3, 4, 5, 6, 7, 9 })
        {
            BigInteger r = BigInteger.One << (64 * limbs);

            // Top limb all ones, like the spec's p: no spare high bits anywhere.
            yield return r - 1;
            yield return r - 59;

            // Top limb tiny: values may carry all-ones limbs right up to it.
            yield return (BigInteger.One << (64 * (limbs - 1))) * 2 + 1;

            // Random odd modulus filling exactly this many limbs.
            byte[] bytes = new byte[8 * limbs];
            random.NextBytes(bytes);
            bytes[^1] |= 0x80;
            bytes[0] |= 1;
            yield return new BigInteger(bytes, isUnsigned: true, isBigEndian: false);
        }
    }

    /// <summary>Operand values for a modulus, all reduced, biased toward long carry chains.</summary>
    private static List<BigInteger> Operands(BigInteger p, int limbCount, Random random)
    {
        BigInteger r = BigInteger.One << (64 * limbCount);
        List<BigInteger> values =
        [
            BigInteger.Zero,
            BigInteger.One,
            p - 1,
            p - 2,
            (p - 1) / 2,
            (r - 1) % p,
            r % p,
            (r - p) % p,
        ];

        // All-ones limbs below the top limb, with the top limb as large as stays below p.
        BigInteger topLimb = p >> (64 * (limbCount - 1));
        BigInteger lowOnes = (BigInteger.One << (64 * (limbCount - 1))) - 1;
        for (BigInteger top = topLimb; top >= 0 && top >= topLimb - 2; top--)
        {
            values.Add(((top << (64 * (limbCount - 1))) | lowOnes) % p);
        }

        // Every limb all ones except one zero limb, which stops the carry partway.
        for (int zero = 0; zero < limbCount; zero++)
        {
            values.Add(((r - 1) ^ (new BigInteger(ulong.MaxValue) << (64 * zero))) % p);
        }

        for (int i = 0; i < 24; i++)
        {
            byte[] bytes = new byte[8 * limbCount + 8];
            random.NextBytes(bytes);
            bytes[^1] = 0;
            values.Add(new BigInteger(bytes, isUnsigned: true, isBigEndian: false) % p);
        }

        return values.Distinct().ToList();
    }

    private static ulong[] Limbs(BigInteger value, int limbCount)
    {
        ulong[] limbs = new ulong[limbCount];
        MontgomeryContext.WriteLimbs(value, limbs);
        return limbs;
    }

    [Fact]
    public void ModuliCoverEveryLoopShape()
    {
        HashSet<int> limbCounts = Moduli().Select(p => MontgomeryContext.For(p).LimbCount).ToHashSet();

        Assert.Superset(new HashSet<int> { 1, 2, 3, 4, 5, 64 }, limbCounts);
    }

    [Fact]
    public void MultiplyAndSquare_RawLimbs_MatchDefinition()
    {
        Random random = new(42);
        int checkedProducts = 0;

        foreach (BigInteger p in Moduli())
        {
            MontgomeryContext context = MontgomeryContext.For(p);
            int s = context.LimbCount;
            BigInteger rInverse = ModInverse(BigInteger.One << (64 * s), p);

            List<BigInteger> operands = Operands(p, s, random);
            ulong[] result = new ulong[s];

            foreach (BigInteger a in operands)
            {
                ulong[] aLimbs = Limbs(a, s);

                context.Square(aLimbs, result);
                Assert.Equal(a * a * rInverse % p, MontgomeryContext.FromLimbs(result));

                // Limit the pair count on the large modulus to keep the test quick.
                foreach (BigInteger b in s > 8 ? operands.Take(12) : operands)
                {
                    context.Multiply(aLimbs, Limbs(b, s), result);
                    Assert.Equal(a * b * rInverse % p, MontgomeryContext.FromLimbs(result));
                    checkedProducts++;
                }
            }
        }

        Assert.True(checkedProducts > 5000, $"Only {checkedProducts} products checked.");
    }

    [Fact]
    public void MultiplyAndSquare_ResultMayAliasOperands()
    {
        Random random = new(7);

        foreach (BigInteger p in Moduli())
        {
            MontgomeryContext context = MontgomeryContext.For(p);
            int s = context.LimbCount;
            List<BigInteger> operands = Operands(p, s, random);
            BigInteger a = operands[^1];
            BigInteger b = p - 1;
            ulong[] expectedProduct = new ulong[s];
            ulong[] expectedSquare = new ulong[s];
            context.Multiply(Limbs(a, s), Limbs(b, s), expectedProduct);
            context.Square(Limbs(a, s), expectedSquare);

            ulong[] left = Limbs(a, s);
            context.Multiply(left, Limbs(b, s), left);
            Assert.Equal(expectedProduct, left);

            ulong[] right = Limbs(b, s);
            context.Multiply(Limbs(a, s), right, right);
            Assert.Equal(expectedProduct, right);

            ulong[] both = Limbs(a, s);
            context.Multiply(both, both, both);
            Assert.Equal(expectedSquare, both);

            ulong[] squared = Limbs(a, s);
            context.Square(squared, squared);
            Assert.Equal(expectedSquare, squared);
        }
    }

    [Fact]
    public void Kernels_RejectShortSpans()
    {
        // The kernels index through refs after a single length check, so that check must hold.
        MontgomeryContext context = MontgomeryContext.Current;
        int s = context.LimbCount;
        ulong[] full = new ulong[s];
        ulong[] shortSpan = new ulong[s - 1];

        Assert.Throws<ArgumentException>(() => context.Multiply(shortSpan, full, full));
        Assert.Throws<ArgumentException>(() => context.Multiply(full, shortSpan, full));
        Assert.Throws<ArgumentException>(() => context.Multiply(full, full, shortSpan));
        Assert.Throws<ArgumentException>(() => context.Square(shortSpan, full));
        Assert.Throws<ArgumentException>(() => context.Square(full, shortSpan));
    }

    private static BigInteger ModInverse(BigInteger value, BigInteger modulus)
    {
        BigInteger oldR = value % modulus, r = modulus, oldS = 1, s = 0;
        while (r != 0)
        {
            BigInteger quotient = oldR / r;
            (oldR, r) = (r, oldR - quotient * r);
            (oldS, s) = (s, oldS - quotient * s);
        }

        Assert.Equal(BigInteger.One, oldR);
        return ((oldS % modulus) + modulus) % modulus;
    }
}
