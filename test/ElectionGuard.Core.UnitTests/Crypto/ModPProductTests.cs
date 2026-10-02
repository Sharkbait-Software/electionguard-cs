using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Crypto;

/// <summary>
/// <see cref="ModPProduct"/>: a running product mod p that loads each factor without converting it
/// into Montgomery form and corrects for the resulting powers of R when read. Every case is checked
/// against the same product computed with BigInteger.
///
/// Each case runs twice, once letting the product pick its engine (AVX-512 where the hardware has
/// it) and once with AVX-512 ruled out, so the scalar fallback is covered on every machine. R differs
/// between the two, which is exactly what the drift correction has to get right.
/// </summary>
public class ModPProductTests
{
    public ModPProductTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static readonly BigInteger P = EGParameters.CryptographicParameters.P;

    public static TheoryData<bool> Engines => new() { true, false };

    [Theory]
    [MemberData(nameof(Engines))]
    public void Multiply_ManyFactors_MatchesBigIntegerProduct(bool allowAvx512)
    {
        Random random = new(20261001);
        ModPProduct product = new(1, allowAvx512);
        BigInteger expected = BigInteger.One;

        for (int i = 0; i < 300; i++)
        {
            BigInteger factor = RandomBelow(random, P);
            product.Multiply(new IntegerModP(factor));
            expected = expected * factor % P;

            // Read part way through as well, so a cached value is invalidated by later factors.
            if (i % 50 == 0)
            {
                Assert.Equal(expected, product.Value.ToBigInteger());
            }
        }

        Assert.Equal(expected, product.Value.ToBigInteger());
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void Multiply_FromNonOneInitialValue_IncludesIt(bool allowAvx512)
    {
        Random random = new(1);
        BigInteger initial = RandomBelow(random, P);
        BigInteger factor = RandomBelow(random, P);

        ModPProduct product = new(new IntegerModP(initial), allowAvx512);
        product.Multiply(new IntegerModP(factor));

        Assert.Equal(initial * factor % P, product.Value.ToBigInteger());
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void Multiply_BoundaryFactors_MatchBigIntegerProduct(bool allowAvx512)
    {
        // p - 1 is the largest residue a factor can be; 0 absorbs everything after it.
        ModPProduct product = new(1, allowAvx512);
        product.Multiply(new IntegerModP(P - 1));
        product.Multiply(new IntegerModP(P - 1));
        Assert.Equal(BigInteger.One, product.Value.ToBigInteger());

        product.Multiply(new IntegerModP(P - 1));
        Assert.Equal(P - 1, product.Value.ToBigInteger());

        product.Multiply(new IntegerModP(0));
        product.Multiply(new IntegerModP(12345));
        Assert.Equal(BigInteger.Zero, product.Value.ToBigInteger());
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void Value_WithNothingMultiplied_IsInitialValue(bool allowAvx512)
    {
        Assert.Equal(new IntegerModP(1), new ModPProduct(1, allowAvx512).Value);
        Assert.Equal(new IntegerModP(P - 1), new ModPProduct(new IntegerModP(P - 1), allowAvx512).Value);
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void MultiplyPower_MatchesModPow(bool allowAvx512)
    {
        Random random = new(2);
        foreach (int exponent in new[] { 0, 1, 2, 3, 7, 255, 256, 1000, 65537, int.MaxValue })
        {
            BigInteger factor = RandomBelow(random, P);
            ModPProduct product = new(1, allowAvx512);
            product.MultiplyPower(new IntegerModP(factor), exponent);

            Assert.Equal(BigInteger.ModPow(factor, exponent, P), product.Value.ToBigInteger());
        }
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void MultiplyPower_InterleavedWithMultiply_MatchesBigIntegerProduct(bool allowAvx512)
    {
        // Powers carry no drift and plain factors do; the two must compose.
        Random random = new(3);
        ModPProduct product = new(1, allowAvx512);
        BigInteger expected = BigInteger.One;

        for (int i = 0; i < 20; i++)
        {
            BigInteger factor = RandomBelow(random, P);
            if (i % 3 == 0)
            {
                product.MultiplyPower(new IntegerModP(factor), i + 2);
                expected = expected * BigInteger.ModPow(factor, i + 2, P) % P;
            }
            else
            {
                product.Multiply(new IntegerModP(factor));
                expected = expected * factor % P;
            }
        }

        Assert.Equal(expected, product.Value.ToBigInteger());
    }

    [Fact]
    public void MultiplyPower_NegativeExponent_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ModPProduct(1).MultiplyPower(new IntegerModP(5), -1));
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void MultiplyProduct_CombinesProductsWithDifferentDrifts(bool allowAvx512)
    {
        Random random = new(4);
        ModPProduct left = new(1, allowAvx512);
        ModPProduct right = new(1, allowAvx512);
        BigInteger expected = BigInteger.One;

        for (int i = 0; i < 7; i++)
        {
            BigInteger factor = RandomBelow(random, P);
            left.Multiply(new IntegerModP(factor));
            expected = expected * factor % P;
        }

        for (int i = 0; i < 12; i++)
        {
            BigInteger factor = RandomBelow(random, P);
            right.Multiply(new IntegerModP(factor));
            expected = expected * factor % P;
        }

        left.Multiply(right);
        Assert.Equal(expected, left.Value.ToBigInteger());

        // Further factors after a merge still land correctly.
        BigInteger last = RandomBelow(random, P);
        left.Multiply(new IntegerModP(last));
        Assert.Equal(expected * last % P, left.Value.ToBigInteger());
    }

    [Avx512Fact]
    public void MultiplyProduct_DifferentRepresentations_Throws()
    {
        ModPProduct avx512 = new(1, allowAvx512: true);
        ModPProduct scalar = new(1, allowAvx512: false);

        Assert.True(avx512.UsesAvx512);
        Assert.False(scalar.UsesAvx512);
        Assert.Throws<ArgumentException>(() => avx512.Multiply(scalar));
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void MultiplyProduct_AfterParameterRoundTrip_StillCombines(bool allowAvx512)
    {
        // Switching p away and back rebuilds the cached engines, so products made before and after
        // hold different engine instances of the same representation. They must still combine.
        ModPProduct before = new(1, allowAvx512);
        before.Multiply(new IntegerModP(7));

        CryptographicParameters small = new(CryptographicParameters.VERSION_DEFAULT, q: "0B", p: "17", r: "02", g: "04");
        using (EGParameters.OverrideScope(small, new GuardianParameters()))
        {
            new ModPProduct(1, allowAvx512).Multiply(new IntegerModP(3));
        }

        ModPProduct after = new(1, allowAvx512);
        after.Multiply(new IntegerModP(11));

        before.Multiply(after);
        Assert.Equal(new IntegerModP(77), before.Value);
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void Reset_DiscardsAccumulatedProduct(bool allowAvx512)
    {
        ModPProduct product = new(1, allowAvx512);
        product.Multiply(new IntegerModP(7));
        product.Multiply(new IntegerModP(11));

        product.Reset(new IntegerModP(13));
        Assert.Equal(new IntegerModP(13), product.Value);

        product.Multiply(new IntegerModP(17));
        Assert.Equal(new IntegerModP(13 * 17), product.Value);

        product.Reset(1);
        product.Multiply(new IntegerModP(19));
        Assert.Equal(new IntegerModP(19), product.Value);
    }

    [Fact]
    public void Value_AlternatingDriftsAndEngines_ShareCorrectionCacheCorrectly()
    {
        // The R^drift correction is cached for the last drift used, across instances. Products with
        // different drifts, and in different representations with the same drift, must each still
        // get their own correction.
        Random random = new(5);
        var products = new List<(ModPProduct Product, BigInteger Expected)>();
        foreach (bool allowAvx512 in new[] { true, false })
        {
            foreach (int count in new[] { 3, 5, 3, 8 })
            {
                ModPProduct product = new(1, allowAvx512);
                BigInteger expected = BigInteger.One;
                for (int i = 0; i < count; i++)
                {
                    BigInteger factor = RandomBelow(random, P);
                    product.Multiply(new IntegerModP(factor));
                    expected = expected * factor % P;
                }

                products.Add((product, expected));
            }
        }

        // Read each product once (an instance caches its own value), in an order that changes the
        // drift or the representation on every read.
        foreach (int index in new[] { 0, 4, 1, 5, 2, 6, 3, 7 })
        {
            Assert.Equal(products[index].Expected, products[index].Product.Value.ToBigInteger());
        }
    }

    [Fact]
    public void Value_ReadConcurrently_IsConsistent()
    {
        Random random = new(6);
        ModPProduct product = new(1);
        BigInteger expected = BigInteger.One;
        for (int i = 0; i < 40; i++)
        {
            BigInteger factor = RandomBelow(random, P);
            product.Multiply(new IntegerModP(factor));
            expected = expected * factor % P;
        }

        var reads = new BigInteger[64];
        Parallel.For(0, reads.Length, i => reads[i] = product.Value.ToBigInteger());

        Assert.All(reads, read => Assert.Equal(expected, read));
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void SmallNonSpecModulus_IsStillCorrect(bool allowAvx512)
    {
        // Tiny moduli take the same engines, and wrap around p constantly.
        CryptographicParameters small = new(CryptographicParameters.VERSION_DEFAULT, q: "0B", p: "17", r: "02", g: "04");
        using (EGParameters.OverrideScope(small, new GuardianParameters()))
        {
            for (int start = 0; start < 23; start++)
            {
                ModPProduct product = new(new IntegerModP(start), allowAvx512);
                BigInteger expected = start;
                for (int factor = 1; factor < 23; factor++)
                {
                    product.Multiply(new IntegerModP(factor));
                    expected = expected * factor % 23;
                }

                product.MultiplyPower(new IntegerModP(start), 5);
                expected = expected * BigInteger.ModPow(start, 5, 23) % 23;

                Assert.Equal(expected, product.Value.ToBigInteger());
            }
        }
    }

    private static BigInteger RandomBelow(Random random, BigInteger bound)
    {
        byte[] bytes = new byte[bound.GetByteCount(isUnsigned: true) + 8];
        random.NextBytes(bytes);
        return new BigInteger(bytes, isUnsigned: true) % bound;
    }
}
