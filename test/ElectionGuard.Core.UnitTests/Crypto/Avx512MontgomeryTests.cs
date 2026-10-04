using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Crypto;

/// <summary>
/// The AVX-512 almost-Montgomery engine, checked against BigInteger. Its values live in a redundant
/// [0, 2p) range rather than [0, p), so these tests deliberately feed it operands from the whole of
/// that range, including the ones a fully reduced representation never sees, and check after every
/// multiplication that the output is still a valid operand: every digit below 2^52 and the value
/// below 2p. An output outside that shape would be accepted silently by the next multiplication and
/// only show up, much later, as a wrong answer.
/// </summary>
public class Avx512MontgomeryTests
{
    public Avx512MontgomeryTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static readonly BigInteger P = EGParameters.CryptographicParameters.P;
    private static readonly BigInteger Q = EGParameters.CryptographicParameters.Q;
    private static readonly BigInteger G = EGParameters.CryptographicParameters.G;
    private static readonly BigInteger TwoP = 2 * P;
    private static readonly BigInteger R = BigInteger.One << (Avx512Montgomery.DigitBits * Avx512Montgomery.Iterations);
    private static readonly BigInteger RInverse = BigInteger.ModPow(R, P - 2, P);

    private static Avx512Montgomery Engine
    {
        get
        {
            Assert.True(Avx512Montgomery.TryGetCurrent(out Avx512Montgomery engine));
            return engine;
        }
    }

    /// <summary>
    /// Operands across [0, 2p): the ends of both halves of the range, values whose digits are all at
    /// the 2^52 - 1 maximum, values with a single high digit, and random values in each half.
    /// </summary>
    private static List<BigInteger> Operands(int seed)
    {
        Random random = new(seed);
        List<BigInteger> values =
        [
            BigInteger.Zero,
            BigInteger.One,
            new BigInteger(2),
            P - 1,
            P,
            P + 1,
            TwoP - 2,
            TwoP - 1,
            (BigInteger.One << Avx512Montgomery.DigitBits) - 1,
            (BigInteger.One << 64) - 1,
            (BigInteger.One << 2048) + 1,
            (BigInteger.One << (Avx512Montgomery.DigitBits * 78)) - 1, // every one of the low 78 digits is 2^52 - 1
            (BigInteger.One << 4095) - 1,
            BigInteger.One << 4095,
        ];

        for (int i = 0; i < 16; i++)
        {
            values.Add(MontgomeryModPTests.RandomBelowP(random));
            values.Add(P + MontgomeryModPTests.RandomBelowP(random));
        }

        Assert.All(values, v => Assert.True(v >= 0 && v < TwoP));
        return values;
    }

    [Avx512Fact]
    public void Multiply_MatchesBigInteger_AcrossTheRedundantRange()
    {
        Avx512Montgomery engine = Engine;
        List<BigInteger> values = Operands(20261001);

        ulong[] a = new ulong[Avx512Montgomery.Lanes];
        ulong[] b = new ulong[Avx512Montgomery.Lanes];
        ulong[] result = new ulong[Avx512Montgomery.Lanes];
        foreach (BigInteger x in values)
        {
            Avx512Montgomery.WriteDigits(x, a);
            foreach (BigInteger y in values)
            {
                Avx512Montgomery.WriteDigits(y, b);
                engine.Multiply(a, b, result);

                AssertValidOperand(result);
                Assert.Equal(x * y * RInverse % P, Avx512Montgomery.FromDigits(result) % P);
            }
        }
    }

    [Avx512Fact]
    public void Multiply_ResultMayAliasEitherOperand()
    {
        Avx512Montgomery engine = Engine;
        BigInteger x = TwoP - 1;
        BigInteger y = P + 12345;
        BigInteger expected = x * y * RInverse % P;

        ulong[] a = new ulong[Avx512Montgomery.Lanes];
        ulong[] b = new ulong[Avx512Montgomery.Lanes];

        Avx512Montgomery.WriteDigits(x, a);
        Avx512Montgomery.WriteDigits(y, b);
        engine.Multiply(a, b, a);
        Assert.Equal(expected, Avx512Montgomery.FromDigits(a) % P);

        Avx512Montgomery.WriteDigits(x, a);
        engine.Multiply(a, b, b);
        Assert.Equal(expected, Avx512Montgomery.FromDigits(b) % P);
    }

    [Avx512Fact]
    public void LongSquaringChain_StaysInRangeAndMatchesBigInteger()
    {
        // An exponentiation never reduces fully until the very end, so the [0, 2p) invariant has to
        // survive thousands of products in a row, not just one.
        Avx512Montgomery engine = Engine;
        foreach (BigInteger start in new[] { TwoP - 1, P - 1, P, MontgomeryModPTests.RandomBelowP(new Random(7)) })
        {
            ulong[] accumulator = new ulong[Avx512Montgomery.Lanes];
            Avx512Montgomery.WriteDigits(start, accumulator);

            // Track the plain value: squaring x*R^k-style digits gives x^2 * R^-1 each step.
            BigInteger expected = start % P;
            for (int i = 0; i < 1000; i++)
            {
                engine.Multiply(accumulator, accumulator, accumulator);
                AssertValidOperand(accumulator);
                expected = expected * expected % P * RInverse % P;
            }

            Assert.Equal(expected, Avx512Montgomery.FromDigits(accumulator) % P);
        }
    }

    [Avx512Fact]
    public void ToMontgomeryAndBack_PreservesValue()
    {
        Avx512Montgomery engine = Engine;
        ulong[] montgomery = new ulong[Avx512Montgomery.Lanes];
        Random random = new(42);

        foreach (BigInteger value in new[] { BigInteger.Zero, BigInteger.One, new BigInteger(2), P - 1, G, MontgomeryModPTests.RandomBelowP(random) })
        {
            engine.ToMontgomery(value, montgomery);
            AssertValidOperand(montgomery);
            Assert.Equal(value * R % P, Avx512Montgomery.FromDigits(montgomery) % P);
            Assert.Equal(value, engine.FromMontgomery(montgomery));
        }
    }

    [Avx512Fact]
    public void FromMontgomery_ReducesEitherRepresentation()
    {
        // A residue may arrive as x or x + p; both must come out as x, and p itself as 0.
        Avx512Montgomery engine = Engine;
        ulong[] digits = new ulong[Avx512Montgomery.Lanes];
        BigInteger x = MontgomeryModPTests.RandomBelowP(new Random(3));
        BigInteger plain = x * RInverse % P;

        Avx512Montgomery.WriteDigits(x, digits);
        Assert.Equal(plain, engine.FromMontgomery(digits));

        Avx512Montgomery.WriteDigits(x + P, digits);
        Assert.Equal(plain, engine.FromMontgomery(digits));

        Avx512Montgomery.WriteDigits(P, digits);
        Assert.Equal(BigInteger.Zero, engine.FromMontgomery(digits));

        Avx512Montgomery.WriteDigits(TwoP - 1, digits);
        Assert.Equal((P - 1) * RInverse % P, engine.FromMontgomery(digits));
    }

    [Avx512Fact]
    public void IsOne_AcceptsBothRepresentationsOfOneAndNothingElse()
    {
        Avx512Montgomery engine = Engine;
        ulong[] digits = new ulong[Avx512Montgomery.Lanes];
        BigInteger rModP = R % P;

        Avx512Montgomery.WriteDigits(rModP, digits);
        Assert.True(engine.IsOne(digits));

        Avx512Montgomery.WriteDigits(rModP + P, digits);
        Assert.True(engine.IsOne(digits));

        foreach (BigInteger other in new[] { BigInteger.Zero, BigInteger.One, rModP + 1, rModP - 1, P })
        {
            Avx512Montgomery.WriteDigits(other, digits);
            Assert.False(engine.IsOne(digits));
        }
    }

    [Avx512Fact]
    public void Pow_MatchesModPow_ForEdgeAndRandomExponents()
    {
        Avx512Montgomery engine = Engine;
        Random random = new(99);
        BigInteger[] bases = [BigInteger.Zero, BigInteger.One, P - 1, G, MontgomeryModPTests.RandomBelowP(random)];
        BigInteger[] exponents =
        [
            BigInteger.Zero,
            BigInteger.One,
            new BigInteger(2),
            new BigInteger(0xFFFF_FFFF),          // the widest exponent on the 1-bit window
            new BigInteger(0x1_0000_0000),        // the narrowest on the 4-bit window
            Q - 1,
            Q,
            MontgomeryModPTests.RandomBelowQ(random),
        ];

        ulong[] result = new ulong[Avx512Montgomery.Lanes];
        foreach (BigInteger basis in bases)
        {
            foreach (BigInteger exponent in exponents)
            {
                engine.PowInto(basis, exponent.ToByteArray(isUnsigned: true, isBigEndian: true), result);
                AssertValidOperand(result);
                Assert.Equal(BigInteger.ModPow(basis, exponent, P), engine.FromMontgomery(result));
            }
        }
    }

    [Avx512Fact]
    public void Pow_PaddedExponent_MatchesUnpadded()
    {
        // Z_q exponents are always padded to 32 bytes so that their window width, and so their
        // operation count, never depends on their value. Leading zero bytes must not change the answer.
        Avx512Montgomery engine = Engine;
        BigInteger basis = MontgomeryModPTests.RandomBelowP(new Random(5));
        ulong[] result = new ulong[Avx512Montgomery.Lanes];

        byte[] padded = new IntegerModQ(new BigInteger(3)).ToByteArray();
        Assert.Equal(32, padded.Length);

        engine.PowInto(basis, padded, result);
        Assert.Equal(BigInteger.ModPow(basis, 3, P), engine.FromMontgomery(result));
    }

    [Avx512Fact]
    public void RaisingToQ_DistinguishesSubgroupMembers()
    {
        // The x^q check of Verifications 2, 6 and 7, through the public entry point that routes to
        // this engine: q must be used as q, never reduced into Z_q.
        Random random = new(11);
        for (int i = 0; i < 4; i++)
        {
            BigInteger member = BigInteger.ModPow(G, MontgomeryModPTests.RandomBelowQ(random), P);
            Assert.Equal(new IntegerModP(BigInteger.One), MontgomeryModP.PowModP(member, Q));
        }

        // 2 is a quadratic residue outside the subgroup; p - 1 is a non-residue.
        foreach (BigInteger nonMember in new[] { new BigInteger(2), P - 1, P - BigInteger.ModPow(G, 5, P) })
        {
            IntegerModP raised = MontgomeryModP.PowModP(nonMember, Q);
            Assert.NotEqual(new IntegerModP(BigInteger.One), raised);
            Assert.Equal(BigInteger.ModPow(nonMember, Q, P), raised.ToBigInteger());
        }
    }

    [Avx512Fact]
    public void PowModP_TableFree_MatchesIntegerModP_ForBothOverloads()
    {
        Random random = new(17);
        for (int i = 0; i < 6; i++)
        {
            BigInteger basis = MontgomeryModPTests.RandomBelowP(random);
            BigInteger exponent = MontgomeryModPTests.RandomBelowQ(random);

            IntegerModP expected = IntegerModP.PowModP(basis, exponent);
            Assert.Equal(expected, MontgomeryModP.PowModP(basis, new IntegerModQ(exponent)));
            Assert.Equal(expected, MontgomeryModP.PowModP(basis, exponent));
        }

        // A raw BigInteger basis outside [0, p) is reduced first.
        Assert.Equal(
            IntegerModP.PowModP(G, new BigInteger(12345)),
            MontgomeryModP.PowModP(G + P, new BigInteger(12345)));
    }

    [Avx512Fact]
    public void PowModP_TableFree_AllocatesOnlyTheResult()
    {
        // Verification runs these from many threads at once, so the exponentiation must not lean on
        // the heap. The result itself is one 4096-bit BigInteger, a little over 512 bytes.
        IntegerModP basis = new(MontgomeryModPTests.RandomBelowP(new Random(1)));
        IntegerModQ exponent = new(MontgomeryModPTests.RandomBelowQ(new Random(2)));
        PowRadixRegistry.Clear();

        MontgomeryModP.PowModP(basis, exponent);
        MontgomeryModP.PowModP(basis, Q);

        long before = GC.GetAllocatedBytesForCurrentThread();
        MontgomeryModP.PowModP(basis, exponent);
        long afterZq = GC.GetAllocatedBytesForCurrentThread();
        MontgomeryModP.PowModP(basis, Q);
        long afterBigInteger = GC.GetAllocatedBytesForCurrentThread();

        Assert.InRange(afterZq - before, 0, 1024);
        Assert.InRange(afterBigInteger - afterZq, 0, 1024);
    }

    [Avx512Fact]
    public void PowModP_IsCorrectUnderConcurrentUse()
    {
        // An instance is shared by every thread; any scratch state on it would show up here.
        BigInteger[] bases = new BigInteger[64];
        BigInteger[] exponents = new BigInteger[64];
        Random random = new(23);
        for (int i = 0; i < bases.Length; i++)
        {
            bases[i] = MontgomeryModPTests.RandomBelowP(random);
            exponents[i] = MontgomeryModPTests.RandomBelowQ(random);
        }

        IntegerModP[] actual = new IntegerModP[bases.Length];
        Parallel.For(0, bases.Length, new ParallelOptions { MaxDegreeOfParallelism = 32 },
            i => actual[i] = MontgomeryModP.PowModP(bases[i], new IntegerModQ(exponents[i])));

        for (int i = 0; i < bases.Length; i++)
        {
            Assert.Equal(BigInteger.ModPow(bases[i], exponents[i], P), actual[i].ToBigInteger());
        }
    }

    [Avx512Fact]
    public void SmallNonSpecModulus_IsStillCorrect()
    {
        // Parameter overrides in other tests use tiny moduli, which also take this engine: R > 4p
        // holds trivially and nothing in the algorithm depends on p filling its digits.
        CryptographicParameters small = new(CryptographicParameters.VERSION_DEFAULT, q: "0B", p: "17", r: "02", g: "04");
        using (EGParameters.OverrideScope(small, new GuardianParameters()))
        {
            Assert.True(Avx512Montgomery.TryGetCurrent(out Avx512Montgomery engine));
            Assert.Equal(new BigInteger(23), engine.Modulus);

            for (int basis = 0; basis < 23; basis++)
            {
                for (int exponent = 0; exponent < 30; exponent++)
                {
                    Assert.Equal(
                        BigInteger.ModPow(basis, exponent, 23),
                        MontgomeryModP.PowModP(new BigInteger(basis), new BigInteger(exponent)).ToBigInteger());
                }
            }
        }

        Assert.True(Avx512Montgomery.TryGetCurrent(out Avx512Montgomery restored));
        Assert.Equal(P, restored.Modulus);
    }

    [Avx512Fact]
    public void BatchedSubgroupCheck_OnThisEngine_StillDetectsNonMembers()
    {
        // SubgroupMembershipTests covers the batch test in general; this pins that on AVX-512
        // hardware it is this engine underneath, and that a quadratic residue outside the subgroup,
        // which only the batched exponentiation can catch, is still caught.
        Assert.True(Avx512Montgomery.TryGetCurrent(out _));
        Random random = new(29);
        List<IntegerModP> values = Enumerable.Range(0, 30)
            .Select(_ => new IntegerModP(BigInteger.ModPow(G, MontgomeryModPTests.RandomBelowQ(random), P)))
            .ToList();

        Assert.Equal(-1, SubgroupMembership.IndexOfFirstNonMember(values));

        values[17] = new IntegerModP(4 * values[17].ToBigInteger() % P);
        Assert.Equal(17, SubgroupMembership.IndexOfFirstNonMember(values));
    }

    [Avx512Theory]
    [InlineData(2)]   // the spec's p minus 2: low digit 2^52 - 3, so k0 = 1/3 mod 2^52, not 1
    [InlineData(-1)]  // a random full-width odd modulus with every digit populated
    public void Multiply_MatchesBigInteger_ForFullWidthModuliWhoseK0IsNotOne(int subtractFromP)
    {
        // The spec's p has its low 256 bits all ones, which makes k0 = -p^-1 mod 2^52 equal to 1 and
        // would hide a kernel that forgot to multiply by it. Montgomery multiplication needs only an
        // odd modulus, so these need not be prime.
        Random random = new(subtractFromP + 100);
        BigInteger modulus;
        if (subtractFromP >= 0)
        {
            modulus = P - subtractFromP;
        }
        else
        {
            byte[] bytes = new byte[512];
            random.NextBytes(bytes);
            modulus = new BigInteger(bytes, isUnsigned: true, isBigEndian: true) | (BigInteger.One << 4095) | BigInteger.One;
        }

        // The units mod 2^52 have order 2^51, so m^(2^51 - 1) is m^-1 there.
        BigInteger digitRadix = BigInteger.One << Avx512Montgomery.DigitBits;
        BigInteger inverse = BigInteger.ModPow(modulus % digitRadix, digitRadix / 2 - 1, digitRadix);
        Assert.NotEqual(BigInteger.One, (digitRadix - inverse) % digitRadix);

        CryptographicParameters parameters = new(CryptographicParameters.VERSION_DEFAULT, q: "0B", p: Convert.ToHexString(modulus.ToByteArray(isUnsigned: true, isBigEndian: true)), r: "02", g: "04");
        using (EGParameters.OverrideScope(parameters, new GuardianParameters()))
        {
            Assert.True(Avx512Montgomery.TryGetCurrent(out Avx512Montgomery engine));
            Assert.Equal(modulus, engine.Modulus);

            BigInteger twoM = 2 * modulus;
            ulong[] a = new ulong[Avx512Montgomery.Lanes];
            ulong[] b = new ulong[Avx512Montgomery.Lanes];
            ulong[] result = new ulong[Avx512Montgomery.Lanes];
            BigInteger[] edges = [BigInteger.Zero, BigInteger.One, modulus - 1, modulus, twoM - 1];
            List<BigInteger> operands = [.. edges];
            for (int i = 0; i < 24; i++)
            {
                byte[] bytes = new byte[520];
                random.NextBytes(bytes);
                operands.Add(new BigInteger(bytes, isUnsigned: true) % twoM);
            }

            foreach (BigInteger x in operands)
            {
                foreach (BigInteger y in operands)
                {
                    Avx512Montgomery.WriteDigits(x, a);
                    Avx512Montgomery.WriteDigits(y, b);
                    engine.Multiply(a, b, result);

                    Assert.All(result, d => Assert.True(d <= Avx512Montgomery.DigitMask, "digit exceeds 2^52 - 1"));
                    BigInteger product = Avx512Montgomery.FromDigits(result);
                    Assert.True(product < twoM, "value is not below 2m");
                    Assert.Equal(x * y % modulus, product * R % modulus);
                }
            }
        }
    }

    [Fact]
    public void FloatingPointConstants_MatchTheirBitPatterns()
    {
        // The kernel reads doubles' bits as integers and subtracts these biases; they must be the
        // exact encodings of the addends it uses, and those addends exact powers of two.
        Assert.Equal(Avx512Montgomery.LowBias, BitConverter.DoubleToUInt64Bits(Avx512Montgomery.TwoPow52));
        Assert.Equal(Avx512Montgomery.HighBias, BitConverter.DoubleToUInt64Bits(Avx512Montgomery.TwoPow104));
        Assert.Equal(BigInteger.One << 52, new BigInteger(Avx512Montgomery.TwoPow52));
        Assert.Equal(BigInteger.One << 104, new BigInteger(Avx512Montgomery.TwoPow104));
        Assert.Equal((BigInteger.One << 104) + (BigInteger.One << 52), new BigInteger(Avx512Montgomery.TwoPow104 + Avx512Montgomery.TwoPow52));
    }

    [Fact]
    public void Fits_RejectsModuliItCannotHandle()
    {
        Assert.True(Avx512Montgomery.Fits(P));
        Assert.True(Avx512Montgomery.Fits(new BigInteger(23)));
        Assert.False(Avx512Montgomery.Fits(P + 1));
        Assert.False(Avx512Montgomery.Fits((BigInteger.One << Avx512Montgomery.MaxModulusBits) + 1));
        Assert.False(Avx512Montgomery.Fits(BigInteger.One));
    }

    [Fact]
    public void Digits_RoundTrip()
    {
        // Pure conversion, no AVX-512 involved, so this runs everywhere.
        ulong[] digits = new ulong[Avx512Montgomery.Lanes];
        foreach (BigInteger value in Operands(8))
        {
            Avx512Montgomery.WriteDigits(value, digits);
            Assert.All(digits, d => Assert.True(d <= Avx512Montgomery.DigitMask));
            Assert.Equal(value, Avx512Montgomery.FromDigits(digits));
        }
    }

    private static void AssertValidOperand(ulong[] digits)
    {
        Assert.All(digits, d => Assert.True(d <= Avx512Montgomery.DigitMask, "digit exceeds 2^52 - 1"));
        Assert.True(Avx512Montgomery.FromDigits(digits) < TwoP, "value is not below 2p");
    }
}
