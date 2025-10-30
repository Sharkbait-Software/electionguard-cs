using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Crypto;

public class ElectionGuardRandomTests
{
    public ElectionGuardRandomTests()
    {
        CryptographicParameters cryptographicParameters = new CryptographicParameters();
        GuardianParameters guardianParameters = new GuardianParameters();
        EGParameters.Init(cryptographicParameters, guardianParameters);
    }

    [Fact]
    public void GetIntegerModQ_Returns_Valid_IntegerModQ()
    {
        // Act
        var result = ElectionGuardRandom.GetIntegerModQ();

        // Assert
        Assert.IsType<IntegerModQ>(result);

        // The value should be >= 0 and < Q
        var value = result.ToBigInteger();
        Assert.True(value >= BigInteger.Zero, "Value should be non-negative");
        Assert.True(value < EGParameters.CryptographicParameters.Q, "Value should be less than Q");
    }

    [Theory]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    public void GetBytes_Returns_Correct_Length(int numBytes)
    {
        // Act
        var bytes = ElectionGuardRandom.GetBytes(numBytes);

        // Assert
        Assert.NotNull(bytes);
        Assert.Equal(numBytes, bytes.Length);
    }

    [Fact]
    public void GetBytes_Returns_Different_Results_On_Subsequent_Calls()
    {
        // Act
        var bytes1 = ElectionGuardRandom.GetBytes(32);
        var bytes2 = ElectionGuardRandom.GetBytes(32);

        // Assert
        Assert.NotEqual(bytes1, bytes2);
    }
}
