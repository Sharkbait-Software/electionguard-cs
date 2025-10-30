using ElectionGuard.Core.Extensions;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Extensions;

public class ByteArrayExtensionsTests
{
    [Fact]
    public void XOR_SameLengthArrays_ReturnsXorResult()
    {
        // Arrange
        var a = new byte[] { 0x0F, 0xF0, 0xAA };
        var b = new byte[] { 0xF0, 0x0F, 0x55 };

        // Act
        var result = a.XOR(b);

        // Assert
        Assert.Equal(new byte[] { 0xFF, 0xFF, 0xFF }, result);
    }

    [Fact]
    public void XOR_DifferentLengthArrays_ThrowsException()
    {
        var a = new byte[] { 0x01, 0x02 };
        var b = new byte[] { 0x01 };

        Assert.Throws<IndexOutOfRangeException>(() => a.XOR(b));
    }

    [Fact]
    public void AsBigInteger_ConvertsCorrectly_Positive()
    {
        // Arrange
        var bytes = new byte[] { 0x01, 0x00 }; // 256 in little-endian

        // Act
        var result = bytes.AsBigInteger();

        // Assert
        Assert.Equal(new BigInteger(256), result);
    }

    [Fact]
    public void AsBigInteger_ConvertsCorrectly_Negative()
    {
        // Arrange
        var bytes = new byte[] { 0xFF, 0xFF }; // 65535 in little-endian, unsigned

        // Act
        var result = bytes.AsBigInteger();

        // Assert
        Assert.Equal(new BigInteger(65535), result);
    }

    [Fact]
    public void Concat_CombinesMultipleArrays()
    {
        // Arrange
        var a = new byte[] { 0x01, 0x02 };
        var b = new byte[] { 0x03 };
        var c = new byte[] { 0x04, 0x05, 0x06 };

        // Act
        var result = ByteArrayExtensions.Concat(a, b, c);

        // Assert
        Assert.Equal(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }, result);
    }

    [Fact]
    public void Concat_EmptyInput_ReturnsEmptyArray()
    {
        // Act
        var result = ByteArrayExtensions.Concat();

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public void PadToLength_PadsCorrectly()
    {
        // Arrange
        var bytes = new byte[] { 0x01, 0x02, 0x03 };

        // Act
        var result = bytes.PadToLength(5);

        // Assert
        Assert.Equal(new byte[] { 0x00, 0x00, 0x01, 0x02, 0x03 }, result);
    }

    [Fact]
    public void PadToLength_ExactLength_ReturnsSameArray()
    {
        // Arrange
        var bytes = new byte[] { 0x01, 0x02, 0x03 };

        // Act
        var result = bytes.PadToLength(3);

        // Assert
        Assert.Equal(new byte[] { 0x01, 0x02, 0x03 }, result);
    }

    [Fact]
    public void PadToLength_ShorterLength_ThrowsException()
    {
        // Arrange
        var bytes = new byte[] { 0x01, 0x02, 0x03 };

        // Act & Assert
        Assert.Throws<Exception>(() => bytes.PadToLength(2));
    }
}
