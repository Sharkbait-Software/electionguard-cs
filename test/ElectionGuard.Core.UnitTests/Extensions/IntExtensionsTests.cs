using ElectionGuard.Core.Extensions;

namespace ElectionGuard.Core.UnitTests.Extensions;

public class IntExtensionsTests
{
    [Theory]
    [InlineData(0, new byte[] { 0, 0, 0, 0 })]
    [InlineData(1, new byte[] { 0, 0, 0, 1 })]
    [InlineData(-1, new byte[] { 255, 255, 255, 255 })]
    [InlineData(0x12345678, new byte[] { 0x12, 0x34, 0x56, 0x78 })]
    [InlineData(int.MaxValue, new byte[] { 0x7F, 0xFF, 0xFF, 0xFF })]
    [InlineData(int.MinValue, new byte[] { 0x80, 0x00, 0x00, 0x00 })]
    public void ToByteArray_ReturnsBigEndianBytes(int value, byte[] expected)
    {
        // Act
        var result = value.ToByteArray();

        // Assert
        Assert.Equal(expected, result);
    }
}
