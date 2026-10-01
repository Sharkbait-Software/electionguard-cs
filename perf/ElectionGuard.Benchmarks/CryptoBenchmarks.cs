using BenchmarkDotNet.Attributes;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Benchmarks;

/// <summary>
/// The primitives everything else is built on. PowModP is expected to dominate every higher-level
/// number, so this is where an optimization to Crypto proves itself first.
/// </summary>
[MemoryDiagnoser]
public class CryptoBenchmarks
{
    private IntegerModP _base;
    private IntegerModQ _exponent;
    private IntegerModP _left;
    private IntegerModP _right;

    // A subgroup element that is deliberately never registered, so exponentiating it exercises the
    // table-free Montgomery path. Comparing it against _base (which is g, and is registered)
    // separates what Montgomery form buys from what the table buys -- the two halves of Note 3.5.
    private IntegerModP _untabledBase;
    // The key length is fixed at 32 by the spec (§5.2); the message length is a free parameter of
    // this benchmark. Keep them as separate fields -- collapsing them back into one would silently
    // shrink the message and change what Hash() measures.
    private byte[] _hashKey = null!;
    private byte[] _hashMessage = null!;

    [GlobalSetup]
    public void Setup()
    {
        _base = new IntegerModP(EGParameters.G);
        _exponent = new IntegerModQ(ElectionGuardRandom.GetBytes(32));
        _left = IntegerModP.PowModP(_base, _exponent);
        _right = IntegerModP.PowModP(_base, new IntegerModQ(ElectionGuardRandom.GetBytes(32)));
        _hashKey = ElectionGuardRandom.GetBytes(32);
        _hashMessage = ElectionGuardRandom.GetBytes(64);

        _untabledBase = IntegerModP.PowModP(EGParameters.G, new IntegerModQ(ElectionGuardRandom.GetBytes(32)));

        PowRadixRegistry.Clear();
        PowRadixRegistry.Precompute(EGParameters.G);
    }

    [GlobalCleanup]
    public void Cleanup() => PowRadixRegistry.Clear();

    [Benchmark(Baseline = true)]
    public IntegerModP PowModP() => IntegerModP.PowModP(_base, _exponent);

    /// <summary>Note 3.5's Montgomery form alone, with no precomputed table.</summary>
    [Benchmark]
    public IntegerModP PowModPMontgomeryTableFree() => MontgomeryModP.PowModP(_untabledBase, _exponent);

    /// <summary>Note 3.5 in full: Montgomery form plus a precomputed table of powers of g.</summary>
    [Benchmark]
    public IntegerModP PowModPMontgomeryTabled() => MontgomeryModP.PowModP(_base, _exponent);

    [Benchmark]
    public IntegerModP MultiplyModP() => _left * _right;

    [Benchmark]
    public IntegerModQ MultiplyModQ() => _exponent * _exponent;

    [Benchmark]
    public byte[] Hash() => EGHash.Hash(_hashKey, _hashMessage);
}
