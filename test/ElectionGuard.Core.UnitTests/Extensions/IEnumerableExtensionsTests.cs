using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Extensions;

public interface IEnumerableExtensionsTests
{
    [Fact]
    public void Sum_IntegerModQ_ReturnsCorrectSum()
    {
        // Arrange
        var items = new[]
        {
            new IntegerModQ(new BigInteger(1)),
            new IntegerModQ(new BigInteger(2)),
            new IntegerModQ(new BigInteger(3))
        };

        // Act
        var result = items.Sum();

        // Assert
        Assert.Equal(new BigInteger(6), result.ToBigInteger());
    }

    [Fact]
    public void Sum_EmptyIntegerModQ_ReturnsZero()
    {
        // Arrange
        var items = Array.Empty<IntegerModQ>();

        // Act
        var result = items.Sum();

        // Assert
        Assert.Equal(BigInteger.Zero, result.ToBigInteger());
    }

    [Fact]
    public void Product_IntegerModP_ReturnsCorrectProduct()
    {
        // Arrange
        var items = new[]
        {
            new IntegerModP(new BigInteger(2)),
            new IntegerModP(new BigInteger(3)),
            new IntegerModP(new BigInteger(4))
        };

        // Act
        var result = items.Product();

        // Assert
        Assert.Equal(new BigInteger(24), result.ToBigInteger());
    }

    [Fact]
    public void Product_EmptyIntegerModP_ThrowsInvalidOperationException()
    {
        // Arrange
        var items = Array.Empty<IntegerModP>();

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => items.Product());
    }

    [Fact]
    public void Product_IntegerModQ_ReturnsCorrectProduct()
    {
        // Arrange
        var items = new[]
        {
            new IntegerModQ(new BigInteger(2)),
            new IntegerModQ(new BigInteger(3)),
            new IntegerModQ(new BigInteger(4))
        };

        // Act
        var result = items.Product();

        // Assert
        Assert.Equal(new BigInteger(24), result.ToBigInteger());
    }

    [Fact]
    public void Product_EmptyIntegerModQ_ThrowsInvalidOperationException()
    {
        // Arrange
        var items = Array.Empty<IntegerModQ>();

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => items.Product());
    }

    [Fact]
    public void Product_Int_ReturnsCorrectProduct()
    {
        // Arrange
        var items = new[] { 2, 3, 4 };

        // Act
        var result = items.Product();

        // Assert
        Assert.Equal(24, result);
    }

    [Fact]
    public void Product_EmptyInt_ThrowsInvalidOperationException()
    {
        // Arrange
        var items = Array.Empty<int>();

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => items.Product());
    }
}
