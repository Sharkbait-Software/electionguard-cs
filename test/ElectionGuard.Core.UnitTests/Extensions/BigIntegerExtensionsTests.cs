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

    [Theory]
    [InlineData(1, 7, 1)]
    [InlineData(3, 7, 5)]
    [InlineData(6, 7, 6)]
    [InlineData(10, 7, 5)]
    [InlineData(-4, 7, 5)]
    [InlineData(2, 101, 51)]
    public void ModInverseVariableTime_SmallModulus_ReturnsInverse(long a, long modulus, long expected)
    {
        Assert.Equal(new BigInteger(expected), new BigInteger(a).ModInverseVariableTime(modulus));
    }

    [Fact]
    public void ModInverseVariableTime_SpecModulus_MatchesFermat()
    {
        BigInteger p = new ElectionGuard.Core.Models.CryptographicParameters().P;
        Random random = new(20261001);

        for (int trial = 0; trial < 20; trial++)
        {
            byte[] bytes = new byte[520];
            random.NextBytes(bytes);
            BigInteger value = new BigInteger(bytes, isUnsigned: true) % (p - 1) + 1;

            BigInteger inverse = value.ModInverseVariableTime(p);

            Assert.Equal(BigInteger.ModPow(value, p - 2, p), inverse);
            Assert.Equal(BigInteger.One, value * inverse % p);
        }
    }

    [Theory]
    [InlineData(0, 7)]
    [InlineData(14, 7)]
    [InlineData(4, 8)]
    public void ModInverseVariableTime_NoInverse_Throws(long a, long modulus)
    {
        Assert.Throws<ArgumentException>(() => new BigInteger(a).ModInverseVariableTime(modulus));
    }

    [Fact]
    public void ModInverseVariableTime_EveryValueOfSmallOddModuli_InvertsOrThrows()
    {
        for (int modulus = 3; modulus < 200; modulus += 2)
        {
            for (int a = 0; a < modulus; a++)
            {
                if (BigInteger.GreatestCommonDivisor(a, modulus).IsOne)
                {
                    BigInteger inverse = new BigInteger(a).ModInverseVariableTime(modulus);
                    Assert.True(inverse >= 0 && inverse < modulus);
                    Assert.Equal(BigInteger.One, a * inverse % modulus);
                }
                else
                {
                    Assert.Throws<ArgumentException>(() => new BigInteger(a).ModInverseVariableTime(modulus));
                }
            }
        }
    }

    [Fact]
    public void ModInverseVariableTime_MultiLimbModulus_CarriesAcrossLimbs()
    {
        // 2^127 - 1 is prime and fills two limbs to the top bit, so halving x + m carries out of them.
        BigInteger modulus = (BigInteger.One << 127) - 1;
        Random random = new(7);

        for (int trial = 0; trial < 200; trial++)
        {
            byte[] bytes = new byte[24];
            random.NextBytes(bytes);
            BigInteger value = new BigInteger(bytes, isUnsigned: true) % (modulus - 1) + 1;

            Assert.Equal(BigInteger.One, value * value.ModInverseVariableTime(modulus) % modulus);
        }
    }
}
