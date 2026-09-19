using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.UnitTests.Models;

public class GuardianParametersTests
{
    [Fact]
    public void DefaultConstructor_KeepsSpecDefaults()
    {
        var parameters = new GuardianParameters();

        Assert.Equal(3, parameters.N);
        Assert.Equal(2, parameters.K);
    }

    [Fact]
    public void Constructor_SetsProvidedThreshold()
    {
        var parameters = new GuardianParameters(5, 3);

        Assert.Equal(5, parameters.N);
        Assert.Equal(3, parameters.K);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(-1, 1)]
    public void Constructor_RejectsNonPositiveN(int n, int k)
    {
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => new GuardianParameters(n, k));

        // Pins that the n check fires before the k check: n is non-positive here, but so is neither
        // k (1) -- if ParamName came back "k", the ordering the constructor documents would be wrong.
        Assert.Equal("n", exception.ParamName);
    }

    [Theory]
    [InlineData(3, 0)]
    [InlineData(3, -1)]
    public void Constructor_RejectsNonPositiveK(int n, int k)
    {
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => new GuardianParameters(n, k));

        Assert.Equal("k", exception.ParamName);
    }

    [Fact]
    public void Constructor_RejectsKGreaterThanN()
    {
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => new GuardianParameters(2, 3));

        // Pins that this is the k>n check specifically, not the earlier k<1 check -- both throw on
        // "k", so ParamName alone doesn't distinguish them, but confirms this branch fires at all
        // for a k that is positive yet still invalid.
        Assert.Equal("k", exception.ParamName);
    }

    [Fact]
    public void Constructor_AllowsKEqualToN()
    {
        var parameters = new GuardianParameters(4, 4);

        Assert.Equal(4, parameters.N);
        Assert.Equal(4, parameters.K);
    }
}
