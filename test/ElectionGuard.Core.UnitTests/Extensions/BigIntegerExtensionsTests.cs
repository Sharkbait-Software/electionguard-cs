using ElectionGuard.Core.Extensions;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Extensions;

public class BigIntegerExtensionsTests
{
    [Theory]
    [InlineData(10, 3, 1)]
    [InlineData(-10, 3, 2)]
    [InlineData(0, 3, 0)]
    [InlineData(3, 3, 0)]
    [InlineData(-3, 3, 0)]
    [InlineData(5, 7, 5)]
    [InlineData(-5, 7, 2)]
    [InlineData(1234567890123456789, 1000000007, 1234567890123456789 % 1000000007)]
    [InlineData(-1234567890123456789, 1000000007, ((-1234567890123456789 % 1000000007) + 1000000007) % 1000000007)]
    public void Mod_PositiveB_ReturnsExpectedResult(long a, long b, long expected)
    {
        // Arrange
        var bigA = new BigInteger(a);
        var bigB = new BigInteger(b);

        // Act
        var result = bigA.Mod(bigB);

        // Assert
        Assert.Equal(new BigInteger(expected), result);
    }
}
