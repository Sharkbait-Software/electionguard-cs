using BenchmarkDotNet.Attributes;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Benchmarks;

/// <summary>
/// How the window width of a Note 3.5 power table trades memory for speed.
///
/// A wider window means fewer rows, and one multiplication per row, so the cost of an
/// exponentiation falls roughly as ceil(|q| / windowBits) while the table grows as 2^windowBits.
/// These are the numbers behind <see cref="PowRadix.DefaultWindowBits"/>.
///
/// 16 is deliberately absent. At the v2.1.0 parameter sizes its table is 512 MB for a single base,
/// and BenchmarkDotNet would build one per iteration of the setup; the perf CLI measures that width
/// instead, once, via --window-bits 16.
/// </summary>
[MemoryDiagnoser]
public class PowRadixBenchmarks
{
    [Params(4, 8, 12)]
    public int WindowBits { get; set; }

    private PowRadix _radix = null!;
    private IntegerModQ _exponent;

    [GlobalSetup]
    public void Setup()
    {
        _exponent = new IntegerModQ(ElectionGuardRandom.GetBytes(32));
        _radix = PowRadix.Build(EGParameters.G, WindowBits);
    }

    [Benchmark]
    public IntegerModP Pow() => _radix.Pow(_exponent);

    /// <summary>
    /// What the table costs to produce. Reported per width so the one-time setup price can be
    /// weighed against the per-exponentiation saving above.
    /// </summary>
    [Benchmark]
    public long Build() => PowRadix.Build(EGParameters.G, WindowBits).TableSizeInBytes;
}
