using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Crypto;

[Collection("PowRadixRegistry")]
public class PowRadixRegistryTests : IDisposable
{
    public PowRadixRegistryTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
        PowRadixRegistry.Clear();
    }

    public void Dispose()
    {
        PowRadixRegistry.Clear();
    }

    private static readonly BigInteger G = EGParameters.CryptographicParameters.G;

    // Narrow windows keep these tests fast; correctness of the wider default is covered by PowRadixTests.
    private const int TestWindowBits = 4;

    [Fact]
    public void TryGet_BeforeAnythingIsPrecomputed_Misses()
    {
        Assert.False(PowRadixRegistry.TryGet(G, out _));
        Assert.Equal(0, PowRadixRegistry.Count);
        Assert.Equal(0, PowRadixRegistry.TotalTableSizeInBytes);
    }

    [Fact]
    public void Precompute_MakesTheBaseFindable()
    {
        PowRadixRegistry.Precompute(TestWindowBits, G);

        Assert.True(PowRadixRegistry.TryGet(G, out PowRadix radix));
        Assert.Equal(G, radix.Basis);
        Assert.Equal(TestWindowBits, radix.WindowBits);
        Assert.Equal(1, PowRadixRegistry.Count);
        Assert.Equal(radix.TableSizeInBytes, PowRadixRegistry.TotalTableSizeInBytes);
    }

    [Fact]
    public void Precompute_LeavesOtherBasesAlone()
    {
        PowRadixRegistry.Precompute(TestWindowBits, G);

        Assert.False(PowRadixRegistry.TryGet(new BigInteger(2), out _));
    }

    [Fact]
    public void Precompute_Twice_ReusesTheExistingTable()
    {
        PowRadixRegistry.Precompute(TestWindowBits, G);
        Assert.True(PowRadixRegistry.TryGet(G, out PowRadix first));

        PowRadixRegistry.Precompute(TestWindowBits, G);
        Assert.True(PowRadixRegistry.TryGet(G, out PowRadix second));

        Assert.Same(first, second);
        Assert.Equal(1, PowRadixRegistry.Count);
    }

    [Fact]
    public void Precompute_AtADifferentWidth_RebuildsTheTable()
    {
        PowRadixRegistry.Precompute(2, G);
        Assert.True(PowRadixRegistry.TryGet(G, out PowRadix narrow));

        PowRadixRegistry.Precompute(4, G);
        Assert.True(PowRadixRegistry.TryGet(G, out PowRadix wider));

        Assert.NotSame(narrow, wider);
        Assert.Equal(4, wider.WindowBits);
        Assert.Equal(1, PowRadixRegistry.Count);
    }

    [Fact]
    public void Precompute_SeveralBases_RegistersEachOne()
    {
        IntegerModP second = IntegerModP.PowModP(G, new IntegerModQ(new BigInteger(5)));

        PowRadixRegistry.Precompute(TestWindowBits, G, second.ToBigInteger());

        Assert.Equal(2, PowRadixRegistry.Count);
        Assert.True(PowRadixRegistry.TryGet(G, out _));
        Assert.True(PowRadixRegistry.TryGet(second, out _));
    }

    [Fact]
    public void Clear_DiscardsEverything()
    {
        PowRadixRegistry.Precompute(TestWindowBits, G);

        PowRadixRegistry.Clear();

        Assert.False(PowRadixRegistry.TryGet(G, out _));
        Assert.Equal(0, PowRadixRegistry.Count);
    }

    [Fact]
    public void TryGet_AfterTheParametersChange_Misses()
    {
        PowRadixRegistry.Precompute(TestWindowBits, G);
        Assert.True(PowRadixRegistry.TryGet(G, out _));

        // A table computed against one p says nothing about another. Reporting a miss sends callers
        // to the table-free path instead of returning values from the wrong group.
        using (EGParameters.OverrideScope(SmallParameters(), new GuardianParameters()))
        {
            Assert.False(PowRadixRegistry.TryGet(G, out _));
            Assert.Equal(0, PowRadixRegistry.Count);
        }

        // Restoring the original parameters makes the table usable again.
        Assert.True(PowRadixRegistry.TryGet(G, out _));
    }

    [Fact]
    public void PowModP_WithATableRegistered_AgreesWithTheTableFreeResult()
    {
        IntegerModQ exponent = new(MontgomeryModPTests.RandomBelowQ(new Random(12345)));

        IntegerModP withoutTable = MontgomeryModP.PowModP(G, exponent);

        PowRadixRegistry.Precompute(TestWindowBits, G);
        IntegerModP withTable = MontgomeryModP.PowModP(G, exponent);

        Assert.Equal(IntegerModP.PowModP(G, exponent), withoutTable);
        Assert.Equal(withoutTable, withTable);
    }

    [Fact]
    public void PowModP_OnlyTabledBasesTakeTheFastPath_ButAllAgree()
    {
        Random random = new(2468);
        BigInteger untabled = MontgomeryModPTests.RandomBelowP(random);
        IntegerModQ exponent = new(MontgomeryModPTests.RandomBelowQ(random));

        PowRadixRegistry.Precompute(TestWindowBits, G);

        Assert.False(PowRadixRegistry.TryGet(untabled, out _));
        Assert.Equal(IntegerModP.PowModP(untabled, exponent), MontgomeryModP.PowModP(untabled, exponent));
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
