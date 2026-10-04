using ElectionGuard.Core.Crypto;

namespace ElectionGuard.Core.UnitTests.Crypto;

/// <summary>
/// A fact that needs AVX-512F, and is reported as skipped rather than passed where the hardware does
/// not have it (or it is disabled with DOTNET_EnableAVX512F=0). xUnit v2 has no way to skip from
/// inside a running test, so the decision is made when the attribute is constructed.
/// </summary>
public sealed class Avx512FactAttribute : FactAttribute
{
    public Avx512FactAttribute()
    {
        if (!Avx512Montgomery.IsSupported)
        {
            Skip = "AVX-512F is not available on this machine.";
        }
    }
}

/// <summary>The <see cref="Avx512FactAttribute"/> equivalent for a theory.</summary>
public sealed class Avx512TheoryAttribute : TheoryAttribute
{
    public Avx512TheoryAttribute()
    {
        if (!Avx512Montgomery.IsSupported)
        {
            Skip = "AVX-512F is not available on this machine.";
        }
    }
}
