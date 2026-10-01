using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Crypto;

/// <summary>
/// Adversarial coverage for the hand-rolled limb arithmetic in <see cref="MontgomeryContext"/>.
///
/// The CIOS multiply propagates carries across 64 limbs, maintains an overflow limb, and ends in a
/// conditional subtraction with its own borrow chain. That is the kind of code where a defect shows
/// up only for particular operand shapes -- a carry that ripples the whole way, a product that just
/// crosses the modulus, a limb that is exactly zero or exactly all ones -- and not for the random
/// values a generic test happens to pick. Random testing finds the bugs that are everywhere;
/// these cases are aimed at the bugs that are somewhere.
///
/// Every assertion compares against BigInteger, which is the oracle: the reference Kotlin
/// implementation computes Montgomery form with BigInteger plus a mask and a shift, and the whole
/// reason this code exists in limb form is that doing so is roughly 2.3x faster. Agreeing with
/// BigInteger everywhere is precisely the property that makes the faster version safe to prefer.
/// </summary>
public class MontgomeryAdversarialTests
{
    public MontgomeryAdversarialTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static readonly BigInteger P = EGParameters.CryptographicParameters.P;
    private static readonly BigInteger Q = EGParameters.CryptographicParameters.Q;
    private static readonly BigInteger G = EGParameters.CryptographicParameters.G;

    /// <summary>
    /// Operand shapes that stress carry propagation, the overflow limb and the final subtraction.
    /// </summary>
    private static List<BigInteger> AdversarialValues()
    {
        List<BigInteger> values =
        [
            BigInteger.Zero,
            BigInteger.One,
            new BigInteger(2),
            new BigInteger(3),

            // Immediately below the modulus: the largest products CIOS ever reduces, and the cases
            // that always need the conditional subtraction.
            P - 1,
            P - 2,
            P - 3,
            P / 2,
            (P - 1) / 2,

            G,
        ];

        // Limb boundaries. A one-off in limb indexing or a carry that fails to ripple past a limb
        // shows up here and almost nowhere else.
        foreach (int bit in new[] { 63, 64, 65, 127, 128, 129, 2047, 2048, 4031, 4032, 4094, 4095 })
        {
            BigInteger power = BigInteger.One << bit;
            values.Add(power % P);
            values.Add((power - 1) % P);
            values.Add((power + 1) % P);
        }

        // All-ones runs force a carry across every limb they span.
        foreach (int limbs in new[] { 1, 2, 7, 8, 32, 63, 64 })
        {
            values.Add(((BigInteger.One << (limbs * 64)) - 1) % P);
        }

        // Alternating bit patterns, which defeat accidental symmetry in a shift-and-mask bug.
        BigInteger alternatingHigh = BigInteger.Zero;
        BigInteger alternatingLow = BigInteger.Zero;
        for (int limb = 0; limb < 64; limb++)
        {
            alternatingHigh |= new BigInteger(0xAAAAAAAAAAAAAAAAUL) << (limb * 64);
            alternatingLow |= new BigInteger(0x5555555555555555UL) << (limb * 64);
        }
        values.Add(alternatingHigh % P);
        values.Add(alternatingLow % P);

        return values.Select(v => v % P).Distinct().ToList();
    }

    /// <summary>
    /// The generators above reduce and de-duplicate, so a mistake there could quietly shrink the
    /// corpus and leave every test in this class passing while covering almost nothing. These
    /// floors make that failure loud instead.
    /// </summary>
    [Fact]
    public void TheAdversarialCorpusIsActuallyPopulated()
    {
        Assert.InRange(AdversarialValues().Count, 40, 200);
        Assert.InRange(AdversarialExponents().Count, 20, 200);

        // The interesting shapes must survive reduction mod p rather than collapsing to 0 or 1.
        List<BigInteger> values = AdversarialValues();
        Assert.Contains(P - 1, values);
        Assert.Contains(G, values);
        Assert.True(values.Count(v => v > BigInteger.One) > 35);
    }

    [Fact]
    public void Multiply_EveryAdversarialPair_MatchesBigInteger()
    {
        List<BigInteger> values = AdversarialValues();

        // Every ordered pair, so asymmetric handling of the two operands cannot hide.
        foreach (BigInteger a in values)
        {
            IntegerModP left = new(a);

            foreach (BigInteger b in values)
            {
                IntegerModP actual = MontgomeryModP.MultiplyMod(left, new IntegerModP(b));

                Assert.Equal(new IntegerModP(a * b % P), actual);
            }
        }
    }

    [Fact]
    public void Square_EveryAdversarialValue_MatchesBigInteger()
    {
        foreach (BigInteger a in AdversarialValues())
        {
            IntegerModP actual = MontgomeryModP.SquareMod(new IntegerModP(a));

            Assert.Equal(new IntegerModP(a * a % P), actual);
        }
    }

    [Fact]
    public void RoundTrip_EveryAdversarialValue_IsLossless()
    {
        foreach (BigInteger a in AdversarialValues())
        {
            IntegerModP original = new(a);

            Assert.Equal(original, MontgomeryModP.RoundTrip(original));
        }
    }

    [Fact]
    public void Multiply_ManyRandomPairs_MatchesBigInteger()
    {
        // Volume, to catch anything the shapes above do not reach. Fixed seed so a failure is
        // reproducible rather than a story about a build that once went red.
        Random random = new(20260930);

        for (int i = 0; i < 750; i++)
        {
            BigInteger a = MontgomeryModPTests.RandomBelowP(random);
            BigInteger b = MontgomeryModPTests.RandomBelowP(random);

            IntegerModP actual = MontgomeryModP.MultiplyMod(new IntegerModP(a), new IntegerModP(b));

            Assert.Equal(new IntegerModP(a * b % P), actual);
        }
    }

    /// <summary>
    /// Exponent shapes that stress the window-digit extraction: all-zero and all-ones bytes, and
    /// values whose windows straddle the 64-bit words the exponent is read out of.
    /// </summary>
    private static List<BigInteger> AdversarialExponents()
    {
        List<BigInteger> exponents =
        [
            BigInteger.Zero,
            BigInteger.One,
            new BigInteger(2),
            Q - 1,
            Q - 2,
            Q / 2,
        ];

        foreach (int bit in new[] { 1, 7, 8, 63, 64, 65, 127, 128, 191, 192, 254, 255 })
        {
            exponents.Add((BigInteger.One << bit) % Q);
            exponents.Add(((BigInteger.One << bit) - 1) % Q);
        }

        // A run of 0xFF bytes exercises the maximum digit at every window position; a run with
        // embedded zero bytes exercises the zero-digit path that is deliberately never skipped.
        byte[] allOnes = Enumerable.Repeat((byte)0xFF, 32).ToArray();
        allOnes[0] = 0x00;
        exponents.Add(new BigInteger(allOnes, isUnsigned: true, isBigEndian: true) % Q);

        byte[] alternating = new byte[32];
        for (int i = 0; i < alternating.Length; i++)
        {
            alternating[i] = (byte)(i % 2 == 0 ? 0x00 : 0xFF);
        }
        exponents.Add(new BigInteger(alternating, isUnsigned: true, isBigEndian: true) % Q);

        return exponents.Select(e => e % Q).Distinct().ToList();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(8)]
    [InlineData(11)]
    public void PowModP_AdversarialExponents_MatchBigIntegerModPow(int windowBits)
    {
        // windowBits 0 means no table at all, so the same exponents also cover the table-free path.
        PowRadixRegistry.Clear();
        try
        {
            if (windowBits > 0)
            {
                PowRadixRegistry.Precompute(windowBits, G);
            }

            foreach (BigInteger exponent in AdversarialExponents())
            {
                IntegerModQ e = new(exponent);

                Assert.Equal(
                    new IntegerModP(BigInteger.ModPow(G, exponent, P)),
                    MontgomeryModP.PowModP(G, e));
            }
        }
        finally
        {
            PowRadixRegistry.Clear();
        }
    }

    [Fact]
    public void PowModP_AdversarialBases_MatchBigIntegerModPow()
    {
        // Bases without a table, so this is the windowed table-free exponentiation rather than the comb.
        PowRadixRegistry.Clear();
        IntegerModQ exponent = new(MontgomeryModPTests.RandomBelowQ(new Random(4242)));
        BigInteger rawExponent = exponent.ToBigInteger();

        foreach (BigInteger basis in AdversarialValues())
        {
            Assert.Equal(
                new IntegerModP(BigInteger.ModPow(basis, rawExponent, P)),
                MontgomeryModP.PowModP(basis, exponent));
        }
    }
}
